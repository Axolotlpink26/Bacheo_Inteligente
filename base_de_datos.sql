-- =====================================================================
--  BACHEO INTELIGENTE Y PRIORIZACIÓN URBANA - CDMX (Alcaldía Gustavo A. Madero)
--  Base de datos MySQL 8.x  ·  Encargado: Daniel Santana Carbajal
--
--  Cómo ejecutarlo (una sola vez):
--     mysql -u root -p < base_de_datos.sql
--  o abre este archivo en MySQL Workbench / extensión MySQL de VS Code y ejecútalo completo.
--
--  Es seguro volver a ejecutarlo: usa IF NOT EXISTS / INSERT IGNORE y no borra datos.
--
--  Tablas:
--     usuarios             cuentas de la página web (rol: usuario | administrador)
--     baches               un renglón por bache físico (ubicación + características)
--     reportes_ciudadanos  quién y cuándo reportó cada bache (de aquí sale num_reportes)
--  Vista:
--     vista_baches         baches + num_reportes (la usa el código Python)
--
--  Privacidad: los baches NO guardan nombre, teléfono ni correo de quien reporta;
--  sólo se enlaza el id_usuario para evitar reportes duplicados de la misma cuenta.
-- =====================================================================

CREATE DATABASE IF NOT EXISTS bacheo_inteligente
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE bacheo_inteligente;

-- ---------------------------------------------------------------------
--  USUARIOS DE LA PÁGINA WEB
--  La contraseña se guarda como hash (pbkdf2:sha256), nunca en texto plano.
--  No se crea ningún administrador aquí a propósito (no hay contraseñas
--  por defecto en el repositorio). Créalo con:
--     python bacheo_inteligente.py crear-admin
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id_usuario      INT AUTO_INCREMENT PRIMARY KEY,
  nombre          VARCHAR(80)  NOT NULL,
  correo          VARCHAR(120) NOT NULL,
  contrasena_hash VARCHAR(255) NOT NULL,
  rol             ENUM('usuario', 'administrador') NOT NULL DEFAULT 'usuario',
  activo          TINYINT(1)   NOT NULL DEFAULT 1,
  fecha_registro  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_usuarios_correo (correo)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
--  BACHES
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS baches (
  id_bache            INT AUTO_INCREMENT PRIMARY KEY,
  calle               VARCHAR(120) NOT NULL,
  colonia             VARCHAR(120) NOT NULL,
  alcaldia            VARCHAR(80)  NOT NULL,
  latitud             DECIMAL(9,6) NOT NULL,
  longitud            DECIMAL(9,6) NOT NULL,
  fecha_registro      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  tamano              ENUM('Pequeño', 'Mediano', 'Grande')        NOT NULL,
  profundidad         ENUM('Superficial', 'Profundo')             NOT NULL,
  transporte_publico  ENUM('Si', 'No')                            NOT NULL,
  frecuencia_transito ENUM('Diario', 'Semanal', 'Ocasional')      NOT NULL,
  accidentes          ENUM('Si', 'No')                            NOT NULL,
  zona_sensible       ENUM('Si', 'No')                            NOT NULL DEFAULT 'No',
  estado              ENUM('Pendiente', 'Atendido')               NOT NULL DEFAULT 'Pendiente',
  comentario          TEXT NULL,
  fecha_atencion      DATETIME NULL,
  id_usuario_registro INT NULL,
  INDEX idx_baches_estado (estado),
  INDEX idx_baches_ubicacion (calle, colonia, alcaldia),
  INDEX idx_baches_coordenadas (latitud, longitud),
  CONSTRAINT chk_baches_latitud  CHECK (latitud  BETWEEN 19.0 AND 19.8),
  CONSTRAINT chk_baches_longitud CHECK (longitud BETWEEN -99.4 AND -98.9),
  CONSTRAINT fk_baches_usuario FOREIGN KEY (id_usuario_registro)
    REFERENCES usuarios (id_usuario) ON DELETE SET NULL
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
--  REPORTES CIUDADANOS (varios vecinos pueden reportar el mismo bache)
--  UNIQUE (id_bache, id_usuario): una cuenta no puede inflar el conteo
--  reportando dos veces el mismo bache. id_usuario NULL = reporte anónimo
--  (consola o datos de demostración); MySQL permite varios NULL en un UNIQUE.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reportes_ciudadanos (
  id_reporte    INT AUTO_INCREMENT PRIMARY KEY,
  id_bache      INT NOT NULL,
  id_usuario    INT NULL,
  fecha_reporte DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_reporte_bache_usuario (id_bache, id_usuario),
  CONSTRAINT fk_reportes_bache FOREIGN KEY (id_bache)
    REFERENCES baches (id_bache) ON DELETE CASCADE,
  CONSTRAINT fk_reportes_usuario FOREIGN KEY (id_usuario)
    REFERENCES usuarios (id_usuario) ON DELETE SET NULL
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
--  VISTA: cada bache con su número de reportes ciudadanos
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vista_baches AS
SELECT b.*, COUNT(r.id_reporte) AS num_reportes
FROM baches b
LEFT JOIN reportes_ciudadanos r ON r.id_bache = b.id_bache
GROUP BY b.id_bache;

-- ---------------------------------------------------------------------
--  DATOS DE DEMOSTRACIÓN (opcional)
--  Ubicaciones y características inventadas para probar el mapa; las coordenadas
--  son aproximadas. Para quitarlos:  DELETE FROM baches WHERE id_bache BETWEEN 1 AND 10;
-- ---------------------------------------------------------------------
INSERT IGNORE INTO baches
  (id_bache, calle, colonia, alcaldia, latitud, longitud, fecha_registro,
   tamano, profundidad, transporte_publico, frecuencia_transito, accidentes, zona_sensible, comentario)
VALUES
  (1,  'Av. Insurgentes Norte',            'Indios Verdes',              'Gustavo A. Madero', 19.495300, -99.119800, '2026-10-02 08:15:00', 'Grande',  'Profundo',    'Si', 'Diario',    'Si', 'Si', 'Hundimiento junto a la salida del Metro; se ha ponchado más de un vehículo.'),
  (2,  'Calzada de Guadalupe',             'Villa Gustavo A. Madero',    'Gustavo A. Madero', 19.484500, -99.117500, '2026-10-03 17:40:00', 'Mediano', 'Profundo',    'Si', 'Diario',    'No', 'Si', 'Cerca de la zona de peregrinación.'),
  (3,  'Av. Montevideo',                   'Lindavista',                 'Gustavo A. Madero', 19.495800, -99.135200, '2026-10-05 09:05:00', 'Mediano', 'Superficial', 'Si', 'Semanal',   'No', 'No', NULL),
  (4,  'Av. Instituto Politécnico Nacional','Residencial Zacatenco',     'Gustavo A. Madero', 19.504000, -99.146500, '2026-10-07 07:50:00', 'Grande',  'Profundo',    'Si', 'Diario',    'Si', 'No', 'Carril de transporte público.'),
  (5,  'Av. Ticomán',                      'San Pedro Zacatenco',        'Gustavo A. Madero', 19.516300, -99.129500, '2026-10-08 19:20:00', 'Pequeño', 'Superficial', 'No', 'Semanal',   'No', 'No', NULL),
  (6,  'Av. 100 Metros',                   'Nueva Industrial Vallejo',   'Gustavo A. Madero', 19.495000, -99.125300, '2026-10-10 06:45:00', 'Mediano', 'Profundo',    'Si', 'Diario',    'Si', 'No', 'Tráfico pesado de carga.'),
  (7,  'Calle Cantera',                    'Cuautepec Barrio Bajo',      'Gustavo A. Madero', 19.538000, -99.139000, '2026-10-12 12:10:00', 'Mediano', 'Profundo',    'No', 'Ocasional', 'No', 'Si', 'Frente a una primaria; sólo un reporte porque hay poca conectividad.'),
  (8,  'Av. Río de los Remedios',          'San Juan de Aragón',         'Gustavo A. Madero', 19.500000, -99.095000, '2026-10-14 16:30:00', 'Grande',  'Superficial', 'Si', 'Diario',    'No', 'No', NULL),
  (9,  'Calzada San Juan de Aragón',       'Aragón La Villa',            'Gustavo A. Madero', 19.462500, -99.075000, '2026-10-16 10:00:00', 'Pequeño', 'Superficial', 'No', 'Ocasional', 'No', 'No', NULL),
  (10, 'Calle Poniente 112',               'Defensores de la República', 'Gustavo A. Madero', 19.478000, -99.138000, '2026-10-18 13:25:00', 'Pequeño', 'Profundo',    'No', 'Semanal',   'Si', 'Si', 'Cerca de una clínica.');

INSERT IGNORE INTO reportes_ciudadanos (id_reporte, id_bache, id_usuario) VALUES
  (1,1,NULL),(2,1,NULL),(3,1,NULL),(4,1,NULL),(5,1,NULL),(6,1,NULL),(7,1,NULL),
  (8,2,NULL),(9,2,NULL),(10,2,NULL),
  (11,3,NULL),(12,3,NULL),(13,3,NULL),(14,3,NULL),(15,3,NULL),
  (16,4,NULL),(17,4,NULL),
  (18,5,NULL),(19,5,NULL),(20,5,NULL),(21,5,NULL),(22,5,NULL),(23,5,NULL),(24,5,NULL),(25,5,NULL),(26,5,NULL),
  (27,6,NULL),(28,6,NULL),(29,6,NULL),(30,6,NULL),
  (31,7,NULL),
  (32,8,NULL),(33,8,NULL),
  (34,9,NULL),
  (35,10,NULL),(36,10,NULL),(37,10,NULL),(38,10,NULL),(39,10,NULL),(40,10,NULL);
