# Inventario de SonarQube Server

Herramienta de solo lectura para recopilar datos de la Web API de SonarQube Server y generar `sonarqube_inventory.json`, como assessment previo a una migración a SonarQube Cloud. Requiere Python 3.11+ y no instala dependencias externas.

## Configuración

Configure las variables de entorno indicadas en `.env.example`. El archivo es solo una plantilla: no cree ni añada credenciales reales al repositorio. La aplicación no carga archivos `.env`.

PowerShell:

```powershell
$env:SONAR_URL = "https://sonarqube.example.com"
$env:SONAR_TOKEN = "token-de-usuario"
$env:OUTPUT_DIR = ".\sonarqube_inventory"
python .\sonar_inventory.py
```

Opcionales: `VERIFY_SSL` (por defecto `true`), `REQUEST_TIMEOUT` (30 segundos) y `LOG_LEVEL` (`INFO`). La opción `VERIFY_SSL=false` desactiva la validación del certificado; úsela solo en entornos controlados.

La autenticación usa `Authorization: Bearer`. El token no se escribe en el inventario ni se muestra en logs. El proceso solo realiza solicitudes HTTP GET.

## Salida y límites de disponibilidad

El inventario JSON incluye información de instancia, estado, versión, plugins, lenguajes, usuario y permisos globales cuando están autorizados; perfiles, reglas activas y changelog; relaciones de herencia reportadas por la instancia; Quality Gates y asociaciones de proyectos disponibles. Las capacidades observadas y motivos de indisponibilidad se incluyen por endpoint en `capabilities`; los recuentos de páginas y elementos se registran en `resources` y en cada recolección paginada.

Los objetos con sufijo `_api` contienen respuestas directas. `quality_profile_differences` se etiqueta como `inferred_by_comparison`: compara reglas activas únicamente cuando la API reporta un padre explícito o un único ancestro; nunca confunde una lista de ancestros múltiples con el padre directo. Las diferencias no demuestran por sí solas si una regla fue añadida o heredada; el informe conserva etiquetas cautelosas. El changelog se recoge por separado para ayudar a identificar activaciones, desactivaciones o modificaciones explícitas cuando la instancia lo expone. La clasificación built-in/personalizado se basa solo en el campo API `isBuiltIn`; si no se entrega, se informa como no disponible.

Los endpoints y parámetros pueden variar por versión, permisos y edición. La herramienta consulta `api/webservices/list`, registra los endpoints V2 que la instancia anuncie y prefiere una operación V2 cuando está publicada con la misma ruta/operación que la clásica (por ejemplo, `api/v2/.../search`). Si esa operación falla o su respuesta no tiene la colección esperada, intenta la API clásica y registra la alternativa utilizada. Continúa con los recursos accesibles; los datos no disponibles no se inventan y quedan marcados. Revise las advertencias de paginación cuando una API no exponga el total o los parámetros de página.

## Validación local

Instale Ruff para desarrollo:

```powershell
python -m pip install -r requirements-dev.txt
```

Ejecute el análisis estático:

```powershell
python -m ruff check .
```

La configuración de Ruff está en `pyproject.toml`. GitHub Actions ejecuta Ruff y
las pruebas unitarias en cada push y pull request.

Para comprobar la aplicación y sus pruebas:

```powershell
python -m unittest discover -s tests -v
```
