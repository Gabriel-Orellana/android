package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

var JWT_SECRET string
var PEPPER string
var dbPool *pgxpool.Pool // Usamos un pool de conexiones en lugar de una sola conexión

// Cargar las variables de entorno
func loadEnvVars() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error al cargar el archivo .env")
	}

	JWT_SECRET = os.Getenv("JWT_SECRET")
	PEPPER = os.Getenv("PEPPER")
}

// Función para verificar si la contraseña es válida usando argon2
func isValidPassword(hashedPassword, providedPassword string) bool {
	passwordWithPepper := providedPassword + PEPPER
	match, err := argon2id.ComparePasswordAndHash(passwordWithPepper, hashedPassword)
	if err != nil {
		log.Println("Error comparando hash:", err)
		return false
	}
	return match
}

// Función para manejar la autenticación de login
func handleLogin(username string, password string, conn *pgxpool.Pool) (map[string]interface{}, error) {
	// Consultamos el usuario desde la base de datos
	var userID int
	var hashedPassword string
	err := conn.QueryRow(context.Background(), "SELECT id_user, password FROM users WHERE username=$1", username).Scan(&userID, &hashedPassword)
	if err != nil {
		return nil, fmt.Errorf("usuario o contraseña incorrectos")
	}

	// Verificamos si la contraseña es válida
	if !isValidPassword(hashedPassword, password) {
		return nil, fmt.Errorf("usuario o contraseña incorrectos")
	}

	// Devolvemos los datos del usuario
	user := map[string]interface{}{
		"userID":   userID,
		"username": username,
	}

	return user, nil
}

// Función para generar el JWT
func generateJWT(user map[string]interface{}) (string, string, error) {
	// Crear token de acceso
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   user["userID"],
		"username": user["username"],
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", "", err
	}

	// Crear token de refresco
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   user["userID"],
		"username": user["username"],
		"iat":      time.Now().Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// Ruta de login
func login(c *gin.Context, conn *pgxpool.Pool) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Parseamos el cuerpo de la solicitud
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(400, gin.H{"error": "Datos incorrectos"})
		return
	}

	// Verificamos si el usuario es válido
	user, err := handleLogin(loginData.Username, loginData.Password, conn)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Generamos los tokens
	accessToken, refreshToken, err := generateJWT(user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error generando los tokens"})
		return
	}

	// Guardamos los tokens en la base de datos
	_, err = conn.Exec(context.Background(), `
		INSERT INTO tokens (id_user, access_token, refresh_token, value) 
		VALUES ($1, $2, $3, $4)`, user["userID"], accessToken, refreshToken, true)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error guardando los tokens"})
		return
	}

	// Respondemos con los tokens
	c.JSON(200, gin.H{
		"message":      "Usuario autenticado exitosamente",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func verifyAndRefreshTokens(accessToken, refreshToken string, conn *pgxpool.Pool) (string, string, error) {
	// 1. Consultar los tokens en la base de datos
	var idToken int
	var userID int
	var dbAccessToken, dbRefreshToken string
	var active bool

	err := conn.QueryRow(context.Background(), `
		SELECT id_token, id_user, access_token, refresh_token, value 
		FROM tokens 
		WHERE access_token=$1 AND refresh_token=$2`,
		accessToken, refreshToken,
	).Scan(&idToken, &userID, &dbAccessToken, &dbRefreshToken, &active)

	if err != nil {
		return "", "", fmt.Errorf("tokens no encontrados o inválidos")
	}

	if !active {
		return "", "", fmt.Errorf("los tokens están desactivados")
	}

	// 2. Verificar el access token
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_SECRET), nil
	})

	if err == nil && token.Valid {
		// Token sigue siendo válido
		return accessToken, refreshToken, nil
	}

	// 3. Intentar verificar el refresh token
	refreshTokenData, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_SECRET), nil
	})

	if err != nil || !refreshTokenData.Valid {
		return "", "", fmt.Errorf("refresh token inválido o expirado")
	}

	// 4.1 Obtener el username desde la base de datos
	var username string
	err = conn.QueryRow(context.Background(), `SELECT username FROM users WHERE id_user = $1`, userID).Scan(&username)
	if err != nil {
		return "", "", fmt.Errorf("no se pudo obtener el nombre de usuario")
	}

	// 4.2 Crear nuevos tokens con el mismo payload que en generateJWT
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   userID,
		"username": username,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})

	newAccessTokenString, err := newAccessToken.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", "", fmt.Errorf("error al firmar nuevo access token")
	}

	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId":   userID,
		"username": username,
		"iat":      time.Now().Unix(),
	})

	newRefreshTokenString, err := newRefreshToken.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", "", fmt.Errorf("error al firmar nuevo refresh token")
	}

	// 5. Desactivar los tokens antiguos
	_, err = conn.Exec(context.Background(), `UPDATE tokens SET value = false WHERE id_token = $1`, idToken)
	if err != nil {
		return "", "", fmt.Errorf("error al desactivar tokens anteriores")
	}

	// 6. Insertar los nuevos tokens
	_, err = conn.Exec(context.Background(), `
		INSERT INTO tokens (id_user, access_token, refresh_token, value) 
		VALUES ($1, $2, $3, $4)`, userID, newAccessTokenString, newRefreshTokenString, true)

	if err != nil {
		return "", "", fmt.Errorf("error al guardar nuevos tokens")
	}

	return newAccessTokenString, newRefreshTokenString, nil
}

func getProducts(c *gin.Context, conn *pgxpool.Pool) {
	var tokens struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}

	if err := c.ShouldBindJSON(&tokens); err != nil {
		c.JSON(400, gin.H{"error": "Faltan los tokens de acceso o refresco"})
		return
	}

	newAccessToken, newRefreshToken, err := verifyAndRefreshTokens(tokens.AccessToken, tokens.RefreshToken, conn)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	rows, err := conn.Query(context.Background(), `SELECT * FROM products`)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error al obtener productos"})
		return
	}
	defer rows.Close()

	products := []map[string]interface{}{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			continue
		}
		rowMap := map[string]interface{}{}
		fields := rows.FieldDescriptions()
		for i, field := range fields {
			key := string(field.Name)

			// Si es la columna "photo", convertir a URL
			if key == "photo" && values[i] != nil {
				photoPath := values[i].(string)
				rowMap[key] = "http://192.168.1.13:8080/" + photoPath
			} else {
				rowMap[key] = values[i]
			}
		}
		products = append(products, rowMap)
	}

	c.JSON(200, gin.H{
		"message":      "Productos obtenidos exitosamente",
		"products":     products,
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
	})
}

func updateProduct(c *gin.Context, conn *pgxpool.Pool) {
	// Obtener el ID del producto desde la URL
	id := c.Param("id")

	// Estructura para los datos del producto
	var productData struct {
		AccessToken   string  `form:"accessToken"`
		RefreshToken  string  `form:"refreshToken"`
		Name          string  `form:"name"`
		Description   string  `form:"description"`
		Stock         int     `form:"stock"`
		Cost          float64 `form:"cost"`
		SalePrice     float64 `form:"sale_price"`
		Revenue       float64 `form:"revenue"`
		Specification string  `form:"specification"` // <-- Nuevo campo
	}

	// Parsear los datos del cuerpo de la solicitud
	if err := c.ShouldBind(&productData); err != nil {
		c.JSON(400, gin.H{"error": "Datos incorrectos"})
		return
	}

	// Verificar y refrescar los tokens de acceso
	newAccessToken, newRefreshToken, err := verifyAndRefreshTokens(productData.AccessToken, productData.RefreshToken, conn)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	// Preparar la consulta para actualizar el producto
	query := `
		UPDATE products
		SET name = $1, description = $2, stock = $3, cost = $4, sale_price = $5, revenue = $6, specification = $7
		WHERE id_product = $8
		RETURNING photo
    `
	var oldPhoto string
	err = conn.QueryRow(context.Background(), query,
		productData.Name, productData.Description, productData.Stock,
		productData.Cost, productData.SalePrice, productData.Revenue,
		productData.Specification, // <-- Agregado aquí
		id,
	).Scan(&oldPhoto)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error al actualizar el producto"})
		return
	}

	// Si se proporciona una nueva imagen
	file, err := c.FormFile("photo")
	if err == nil {
		// Si existe una imagen anterior, hacer una copia de respaldo
		if oldPhoto != "" {
			// Respaldo de la imagen anterior (puedes incluir un timestamp si quieres)
			backupPath := "./img/backup_" + filepath.Base(oldPhoto)
			err := os.Rename(oldPhoto, backupPath)
			if err != nil {
				c.JSON(500, gin.H{"error": "Error al respaldar la imagen anterior"})
				return
			}
		}

		// Generar un nombre único para la nueva imagen para evitar sobrescribir
		newPhotoPath := "img/" + id + "_" + fmt.Sprintf("%d", time.Now().Unix()) + filepath.Ext(file.Filename)

		// Guardar la nueva imagen
		if err := c.SaveUploadedFile(file, newPhotoPath); err != nil {
			c.JSON(500, gin.H{"error": "Error al guardar la imagen"})
			return
		}

		// Actualizar la ruta de la imagen en la base de datos
		_, err = conn.Exec(context.Background(),
			`UPDATE products SET photo = $1 WHERE id_product = $2`,
			newPhotoPath, id,
		)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error al actualizar la imagen"})
			return
		}
	}

	// Devolver la respuesta
	c.JSON(200, gin.H{
		"message":      "Producto actualizado exitosamente",
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
	})
}

func addProduct(c *gin.Context, conn *pgxpool.Pool) {
	// Estructura para los datos del producto
	var productData struct {
		AccessToken   string  `form:"accessToken"`
		RefreshToken  string  `form:"refreshToken"`
		Name          string  `form:"name"`
		Description   string  `form:"description"`
		Stock         int     `form:"stock"`
		Cost          float64 `form:"cost"`
		SalePrice     float64 `form:"sale_price"`
		Revenue       float64 `form:"revenue"`
		Specification string  `form:"specification"`
	}

	// Parsear los datos del cuerpo de la solicitud
	if err := c.ShouldBind(&productData); err != nil {
		c.JSON(400, gin.H{"error": "Datos incorrectos"})
		return
	}

	// Verificar y refrescar los tokens de acceso
	newAccessToken, newRefreshToken, err := verifyAndRefreshTokens(productData.AccessToken, productData.RefreshToken, conn)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	// Insertar el nuevo producto en la base de datos
	query := `
		INSERT INTO products (name, description, stock, cost, sale_price, revenue, specification)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id_product
	`
	var productID int
	err = conn.QueryRow(context.Background(), query,
		productData.Name, productData.Description, productData.Stock,
		productData.Cost, productData.SalePrice, productData.Revenue,
		productData.Specification,
	).Scan(&productID)

	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("Error al insertar el producto: %v", err)})
		return
	}

	// Si se proporciona una imagen
	file, err := c.FormFile("photo")
	if err == nil {
		// Generar un nombre único para la nueva imagen para evitar sobrescribir
		newPhotoPath := "img/" + fmt.Sprintf("%d", productID) + "_" + fmt.Sprintf("%d", time.Now().Unix()) + filepath.Ext(file.Filename)

		// Guardar la nueva imagen
		if err := c.SaveUploadedFile(file, newPhotoPath); err != nil {
			c.JSON(500, gin.H{"error": fmt.Sprintf("Error al guardar la imagen: %v", err)})
			return
		}

		// Actualizar la ruta de la imagen en la base de datos
		_, err = conn.Exec(context.Background(),
			`UPDATE products SET photo = $1 WHERE id_product = $2`,
			newPhotoPath, productID,
		)
		if err != nil {
			c.JSON(500, gin.H{"error": fmt.Sprintf("Error al actualizar la imagen: %v", err)})
			return
		}
	}

	// Devolver la respuesta
	c.JSON(200, gin.H{
		"message":      "Producto agregado exitosamente",
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken,
	})
}

// Función para cerrar sesión
func logout(c *gin.Context, conn *pgxpool.Pool) {
	var tokens struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}

	// Parseamos los tokens de la solicitud
	if err := c.ShouldBindJSON(&tokens); err != nil {
		c.JSON(400, gin.H{"error": "Faltan los tokens de acceso o refresco"})
		return
	}

	// Consultamos si los tokens existen en la base de datos
	_, err := conn.Exec(context.Background(), `
		UPDATE tokens
		SET value = false
		WHERE access_token = $1 AND refresh_token = $2 AND value = true
	`, tokens.AccessToken, tokens.RefreshToken)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error al cerrar sesión"})
		return
	}

	// Respondemos con éxito
	c.JSON(200, gin.H{
		"message": "Sesión cerrada exitosamente",
	})
}

func main() {
	// Cargar las variables de entorno
	loadEnvVars()

	// Configuración de la base de datos
	dbUser := os.Getenv("DB_USER")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbPort := os.Getenv("DB_PORT")
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	// Conectar a la base de datos usando el pool
	var err error
	dbPool, err = pgxpool.New(context.Background(), connStr)
	if err != nil {
		log.Fatalf("No se pudo conectar al pool de base de datos: %v", err)
	}
	defer dbPool.Close() // Asegúrate de cerrar el pool cuando termine la app

	fmt.Println("Conexión exitosa al pool de base de datos!")

	// Configuración del servidor Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Rutas
	r.POST("/login", func(c *gin.Context) {
		login(c, dbPool) // Pasamos el pool de conexiones
	})

	r.POST("/products", func(c *gin.Context) {
		getProducts(c, dbPool) // Pasamos el pool de conexiones
	})

	r.PUT("/update-products/:id", func(c *gin.Context) {
		updateProduct(c, dbPool)
	})

	r.POST("/add-product", func(c *gin.Context) {
		addProduct(c, dbPool)
	})

	r.POST("/logout", func(c *gin.Context) {
		logout(c, dbPool) // Pasamos el pool de conexiones
	})

	// Servir imágenes estáticas
	r.Static("/img", "./Img")

	// Levantamos el servidor en el puerto 8080
	fmt.Println("Servidor corriendo en http://localhost:8080")
	r.Run(":8080")
}
