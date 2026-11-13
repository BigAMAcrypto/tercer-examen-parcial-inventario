# Sistema de inventario de refacciones

Aplicación web (Flask + SQLite + HTML/CSS) para controlar piezas y refacciones de una empresa de mantenimiento industrial, con tres roles: administrador, gerente y técnico.


## Cuentas de prueba

| Rol | Usuario | Contraseña |
|---|---|---|
| Administrador | admin | admin123 |
| Gerente | gerente | gerente123 |
| Técnico | tecnico / tecnico2 | tecnico123 |

## Permisos

- **Administrador:** alta, edición y eliminación de piezas, entradas de inventario, gestión de usuarios, movimientos y reportes.
- **Gerente:** consulta de inventario, aprobación o rechazo de solicitudes (la aprobación descuenta existencias y registra la salida), movimientos y reportes (CSV).
- **Técnico:** consulta y búsqueda de piezas, solicitud de materiales y seguimiento de sus solicitudes.
