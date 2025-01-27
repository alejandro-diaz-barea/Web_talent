# Informe técnico Talent ScoutTech

## Parte 1 - SQLi
1.a)
Cuando se inyecta en el campo usuario el valor ' " ' , lanza un error que nos dice la consulta completa que realiza a la base de datos
![[Pasted image 20250120113604.png]]


| **Preguntas**                                                      | **Respuestas**                                         |
| ------------------------------------------------------------------ | ------------------------------------------------------ |
| **Escribo los valores ...**                                        | `"`                                                    |
| **En el campo ...**                                                | Usuario                                                |
| **Del formulario de la página ...**                                | Login                                                  |
| **La consulta SQL que se ejecuta es ...**                          | `SELECT userId, password FROM users WHERE username=""` |
| **Campos del formulario web utilizados en la consulta SQL ...**    | `username`                                             |
| **Campos del formulario web NO utilizados en la consulta SQL ...** | `password`                                             |


1.b) 

Dado que la consulta SQL utilizada para autenticar usuarios en la base de datos es:

```sql
SELECT userId, password FROM users WHERE username="";
```

Se ha llevado a cabo un ataque de **fuzzing** utilizando un diccionario de contraseñas, en el cual se ha probado la siguiente inyección en el campo de **usuario**:

```
" OR password="1234" -- -
```

Y en el campo de **contraseña**:

```
1234
```

Este ataque permite eludir la autenticación al forzar que la consulta SQL devuelva resultados sin necesidad de conocer un usuario válido.

Como se ve en la imagen , la carga de datos devuelta en **bytes** es mucho  mayor en comparación con los intentos fallidos, lo que indica que nos dique que el acceso ha sido exitoso.

Este método nos da una vulnerabilidad de **inyección SQL**, permitiendo a un atacante autenticarse sin conocer credenciales legítimas, simplemente explotando contraseñas.

| **Preguntas**                                             | **Respuestas**                                                                                                                  |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Explicación del ataque**                                | El ataque consiste en repetir consultas SQL modificadas utilizando en cada interacción una contraseña diferente del diccionario |
| **Campo de usuario con que el ataque ha tenido éxito**    | `username`                                                                                                                      |
| **Campo de contraseña con que el ataque ha tenido éxito** | `password`                                                                                                                      |



!()[Pasted image 20250120120731.png]



1.c) 

En la función `areUserAndPasswordValid` dentro de `private/auth.php`, se utiliza `SQLite3::escapeString()`, lo qie  **no es suficiente** para prevenir inyecciones SQL.

 **Explicación del error**

La consulta SQL está construida de manera **insegura** concatenando directamente los valores de `$user` en la consulta:

```php
$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
```

`SQLite3::escapeString()` **solo escapa caracteres especiales**, pero no impide una **inyección SQL** si el atacante introduce una consulta. Esto permite a un atacante manipular la consulta SQL y autenticarse sin credenciales válidas.

 **Solución**

Para corregir esta vulnerabilidad, se debe usar **consultas preparadas** en lugar de concatenar directamente variables en la consulta.

**Código inseguro:**

```php
$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
```

**Código corregido usando consultas preparadas:**

```php
$stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');
$stmt->bindValue(':username', $user, SQLITE3_TEXT);
$result = $stmt->execute();
```

Esto evitas las inyecciones porque trata a la variable username como un texto en vez de como parte de la consulta directamente.

| **Preguntas**             | **Respuestas**                                                                  |
| ------------------------- | ------------------------------------------------------------------------------- |
| **Explicación del error** | Se concatena directamente la entrada del usuario en la consulta                 |
| **Solución**              | Cambiar la línea con el código inseguro por la versión con consultas preparadas |

## Parte 2 - XSS

2.a) 

| **Introduzco el mensaje ...**               | **En el formulario de la página ...**            |
|---------------------------------------------|--------------------------------------------------|
| `<script>alert('hola')</script>`            | En el formulario de comentarios de la página    |

![[Pasted image 20250121123314.png]]

![[Pasted image 20250121123230.png]]

2.b)

&amp; se usa en HTML porque & tiene un significado especial: introduce entidades HTML. Si escribes & directamente en un enlace con parámetros GET, el navegador podría confundirlo con una entidad, causando errores algunos casos. Por eso, en HTML, se usa &amp. 
![[Pasted image 20250121123852.png]]

2.c)

Como se puede ver en el código para hacer la consulta a la base de datos mete el parámetro id tal y como lo recibe de la página sin validación ninguna esto es un problema porque se puede ejecutar SQL inyection

![[Pasted image 20250121124546.png]]

2.d)

| **Otras páginas afectadas ...** | buscador.php                                                                                                                        |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **¿Cómo lo he descubierto?**    | Ocurre en el buscador de jugadores y me he dado cuenta por el código, el cual mete la variable directamente en la consulta tambien. |

![[Pasted image 20250121125149.png]]

## Parte 3 - Control de acceso, autenticación y sesiones de usuarios

3.1)

 **Mejoras aplicables a ```register.php ``` :**

-  **Protección contra SQL Injection** con consultas preparadas (`prepare()` y `bindValue()`).  
- **Hasheo seguro de contraseñas** con `password_hash()` en lugar de guardarlas en texto plano.  
- **Validación de entradas** para asegurar que el username solo tenga caracteres permitidos y que la contraseña sea segura.  
-  **Evitar cuentas duplicadas**, verificando si el usuario ya existe antes de insertarlo.  
- **Protección contra CSRF** añadiendo un token único en la sesión.

```php
<?php
session_start();
require_once dirname(__FILE__) . '/private/conf.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verificación del token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Token CSRF inválido.");
    }

    // Validación del nombre de usuario
    if (!preg_match("/^[a-zA-Z0-9_]{3,20}$/", $_POST['username'])) {
        die("El nombre de usuario solo puede contener letras, números y guiones bajos, y debe tener entre 3 y 20 caracteres.");
    }

    // Validación de la contraseña
    if (strlen($_POST['password']) < 8) {
        die("La contraseña debe tener al menos 8 caracteres.");
    }

    // Conexión a la base de datos
    $db = new SQLite3('database.db');

    // Verificar si el usuario ya existe
    $checkUser = $db->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
    $checkUser->bindValue(':username', $_POST['username'], SQLITE3_TEXT);
    $result = $checkUser->execute()->fetchArray();
    if ($result[0] > 0) {
        die("El usuario ya existe.");
    }

    // Hashear la contraseña antes de almacenarla
    $hashedPassword = password_hash($_POST['password'], PASSWORD_BCRYPT);

    // Inserción segura en la base de datos con consulta preparada
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindValue(':username', $_POST['username'], SQLITE3_TEXT);
    $stmt->bindValue(':password', $hashedPassword, SQLITE3_TEXT);
    $stmt->execute();

    // Redirección tras el registro exitoso
    header("Location: list_players.php");
    exit();
}

// Generación del token CSRF
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

```


3.2)

 **Mejoras aplicables a ```list_players.php ``` :**

- **Consultas preparadas** (`prepare()` y `bindValue()`) para evitar SQL Injection.  
- **Hasheo seguro de contraseñas** con `password_hash()`.  
-  **Límite de intentos de login** para evitar ataques de fuerza bruta.  
- **Protección CSRF** con tokens en formularios.  
- **Sesiones seguras** con regeneración de ID y cookies protegidas.

```php
<?php
session_start();
require_once dirname(__FILE__) . '/private/conf.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Token CSRF inválido.");
    }

    // Verificar intentos de inicio de sesión
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }

    if ($_SESSION['login_attempts'] >= 5) {
        die("Demasiados intentos fallidos. Inténtalo más tarde.");
    }

    // Validar entrada
    if (empty($_POST['username']) || empty($_POST['password'])) {
        die("Usuario y contraseña son obligatorios.");
    }

    $db = new SQLite3('database.db');

    // Consulta segura con prepared statements
    $stmt = $db->prepare("SELECT password FROM users WHERE username = :username");
    $stmt->bindValue(':username', $_POST['username'], SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray();

    if ($user && password_verify($_POST['password'], $user['password'])) {
        session_regenerate_id(true); // Proteger contra secuestro de sesión
        $_SESSION['username'] = $_POST['username'];
        $_SESSION['login_attempts'] = 0; // Reiniciar intentos fallidos
        header("Location: list_players.php");
        exit();
    } else {
        $_SESSION['login_attempts']++; // Aumentar intentos fallidos
        die("Usuario o contraseña incorrectos.");
    }
}

// Generar token CSRF para el formulario
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

```

3.c)

 **Mejoras aplicables a ```register.php ``` :**

- **Bloqueo de acceso a usuarios no autenticados**: Ahora solo los usuarios logueados pueden acceder.  
- **Restricción por rol**: Solo los administradores pueden registrar usuarios.

```php
<?php
session_start();
require_once dirname(__FILE__) . '/private/conf.php';

// Verificar si el usuario está logueado
if (!isset($_SESSION['username'])) {
    die("Acceso denegado. Debes estar autenticado.");
}

// Conexión a la base de datos
$db = new SQLite3('database.db');

// Verificar si el usuario es administrador
$stmt = $db->prepare("SELECT role FROM users WHERE username = :username");
$stmt->bindValue(':username', $_SESSION['username'], SQLITE3_TEXT);
$result = $stmt->execute()->fetchArray();

if (!$result || $result['role'] !== 'admin') {
    die("Acceso restringido. Solo los administradores pueden registrar usuarios.");
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verificación del token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Token CSRF inválido.");
    }

    // Validación del nombre de usuario
    if (!preg_match("/^[a-zA-Z0-9_]{3,20}$/", $_POST['username'])) {
        die("El nombre de usuario solo puede contener letras, números y guiones bajos, y debe tener entre 3 y 20 caracteres.");
    }

    // Validación de la contraseña
    if (strlen($_POST['password']) < 8) {
        die("La contraseña debe tener al menos 8 caracteres.");
    }

    // Verificar si el usuario ya existe
    $checkUser = $db->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
    $checkUser->bindValue(':username', $_POST['username'], SQLITE3_TEXT);
    $result = $checkUser->execute()->fetchArray();
    if ($result[0] > 0) {
        die("El usuario ya existe.");
    }

    // Hashear la contraseña antes de almacenarla
    $hashedPassword = password_hash($_POST['password'], PASSWORD_BCRYPT);

    // Inserción segura en la base de datos con consulta preparada
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    $stmt->bindValue(':username', $_POST['username'], SQLITE3_TEXT);
    $stmt->bindValue(':password', $hashedPassword, SQLITE3_TEXT);
    $stmt->execute();

    // Redirección tras el registro exitoso
    header("Location: list_players.php");
    exit();
}

// Generación del token CSRF
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

```

3.d)

![[Pasted image 20250125111826.png]]

Como se puede ver no tenemos acceso por lo que no hay que implementar nada

3.e)

Ya lo tengo arreglado en las demás partes de este apartado

## Parte 4

Para reducir el riesgo de ataques a el servidor web, he pensado en  implementar un **Firewall de Aplicaciones Web (WAF)**, como Cloudflare, para filtrar tráfico malicioso y proteger contra ataques DDoS a nivel de la aplicación. Un **equilibrador de cargas**, como NGINX , también es importante para distribuir las solicitudes entre servidores. Hay que asegurarse de usar HTTPS con certificados TLS y deshabilita protocolos inseguros como SSL 2.0 y TLS 1.0. Hay que implementar **protección contra CSRF**, usando tokens y cookies con la propiedad `SameSite` para evitar solicitudes maliciosas. Limitar los intentos de inicio de sesión y combina esto con CAPTCHA en formularios críticos para mitigar ataques de fuerza bruta. Como último , mantén el servidor y las aplicaciones **actualizados**.

## Parte 5 - CSRF

5.a)

En el campo -> "Team name"
Introduzco ->  
```html
<button><a href="http://web.pagos/donate.php?amount=100&receiver=attacker">click</a></button>
```

![[Pasted image 20250121131840.png]]

5.b)

En el campo -> "comentario"
Introduzco ->

```html
<script>
    window.location.href = "http://web.pagos/donate.php?amount=100&receiver=attacker";
</script>
```

5.c)

- El usuario debe estar autenticado y tener una sesión activa en _web.pagos_.
- El navegador del usuario debe enviar las cookies de autenticación con la solicitud.
- El servidor no debe implementar medidas de protección contra CSRF (como anti-CSRF).

5.d)

Modificar la página donate.php para que reciba los parámetros a través de POST en lugar de GET no blinda completamente contra este tipo de ataques. Aunque el cambio de método hace mas dificil los ataques simples mediante enlaces (como los del apartado a), no protege contra ataques más fuertes, como los realizados mediante CSRF.

Esto pasa porque si el usuario está autenticado en web.pagos y el servidor no implementa protección contra CSRF, un atacante aún podría enviar una solicitud POST desde otro sitio web que el usuario visite.

Un ataque como el del apartado b, pero aplicado a este caso sería así:

```html
<html>
    <body>
        <form id="csrfForm" action="http://web.pagos/donate.php" method="POST">
            <input type="hidden" name="amount" value="100">
            <input type="hidden" name="receiver" value="attacker">
        </form>
        <script>
            // Enviar automáticamente el formulario al cargar la página
            document.getElementById('csrfForm').submit();
        </script>
    </body>
</html>

```

Aún así cuando lo he aplicado da este mensaje
![[Pasted image 20250121134100.png]]
