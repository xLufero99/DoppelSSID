# DoppelSSID — Style Reference
> indigo-ink terminal on deep slate

**Theme:** dark

Adaptado de un lenguaje tipográfico tipo Stripe (whisper-weight, espaciado generoso, sin sombras) para un panel de seguridad de red: fondo oscuro tipo terminal, un único acento indigo para acciones, y una paleta semántica independiente (verde/ámbar/rojo) reservada exclusivamente para estados de riesgo. Los datos técnicos (MAC, BSSID, IP) usan una fuente monoespaciada; todo lo demás usa la tipografía whisper-weight.

## Tokens — Colors

### Superficies y texto

| Name | Value | Token | Role |
|------|-------|-------|------|
| Canvas | `#0a0e17` | `--color-canvas` | Fondo general de la página, casi negro con tinte azul frío |
| Surface | `#11151f` | `--color-surface` | Tarjetas, tablas, paneles |
| Surface Raised | `#171c28` | `--color-surface-raised` | Elementos sobre una tarjeta: inputs, filas en hover, dropdowns |
| Border | `#232a38` | `--color-border` | Borde estándar de tarjetas, tablas e inputs |
| Border Soft | `#1a1f2b` | `--color-border-soft` | Divisores internos muy sutiles (entre filas) |
| Text Primary | `#e8ecf5` | `--color-text-primary` | Texto principal, encabezados, valores destacados |
| Text Secondary | `#8b96ab` | `--color-text-secondary` | Texto de apoyo, descripciones, labels |
| Text Muted | `#5b6577` | `--color-text-muted` | Texto terciario: timestamps, placeholders, ayuda |

### Acento (acción)

| Name | Value | Token | Role |
|------|-------|-------|------|
| Indigo Ink | `#6d5bf7` | `--color-indigo-ink` | Único color de acción: botones primarios, links, estado activo de navegación, foco de inputs |
| Indigo Hover | `#8a7bff` | `--color-indigo-hover` | Hover/estado activo sobre elementos indigo |
| Indigo Wash | `#1a1733` | `--color-indigo-wash` | Fondo tenue para tags o filas resaltadas por el usuario (ej. "red de confianza") |
| Indigo Border | `#3b3570` | `--color-indigo-border` | Borde de botones outline indigo |

### Semántico (estados de riesgo — EXCLUSIVO para alertas, nunca decorativo)

| Name | Value | Token | Role |
|------|-------|-------|------|
| Safe Green | `#34d399` | `--color-safe` | Estado "segura": texto, borde izquierdo de fila, badge |
| Safe Green Wash | `#0d2420` | `--color-safe-wash` | Fondo tenue de badge/fila en estado seguro |
| Caution Amber | `#fbbf24` | `--color-caution` | Estado "precaución": texto, borde izquierdo de fila, badge |
| Caution Amber Wash | `#2a2210` | `--color-caution-wash` | Fondo tenue de badge/fila en estado precaución |
| Risk Red | `#f87171` | `--color-risk` | Estado "riesgo": texto, borde izquierdo de fila, badge |
| Risk Red Wash | `#2a1414` | `--color-risk-wash` | Fondo tenue de badge/fila en estado riesgo |
| Neutral Gray | `#94a3b8` | `--color-neutral` | Estado "oculta" u otros estados informativos sin carga de riesgo |
| Neutral Gray Wash | `#1c212c` | `--color-neutral-wash` | Fondo tenue de badge/fila en estado neutral |

**Regla de oro:** el indigo nunca se usa para indicar riesgo ni seguridad, y los colores semánticos nunca se usan para botones de acción genéricos ni navegación. Son dos sistemas de color que no se mezclan.

## Tokens — Typography

### sohne-var — tipografía principal (texto general, encabezados, UI)
- **Substitute:** Inter Tight (variable, weight 300/400) o similar sans humanista de x-height alto
- **Weights:** 300 (headings, body), 400 (navegación, botones, labels pequeños)
- **Sizes:** 12, 14, 16, 18, 20, 22, 26, 32, 48
- **Line height:** 1.00, 1.03, 1.10, 1.12, 1.20, 1.40, 1.45
- **Letter spacing:** -0.01em hasta 26px; -0.02em entre 32–48px
- **OpenType features:** `"ss01" on, "tnum" on` (numerales tabulares, esenciales para tablas de señal/canal/consumo)
- **Nota:** se omite el tamaño display de 56px del original — este proyecto es un dashboard denso, no una landing page; 48px es el techo (usado solo en el stat de resumen, ej. "25 redes seguras")

### jetbrains-mono — tipografía técnica (MAC, BSSID, IP, SSID crudo, JSON, código)
- **Substitute:** 'JetBrains Mono', ui-monospace, 'SF Mono', Consolas, monospace
- **Weight:** 400 únicamente
- **Sizes:** 12, 13, 14
- **Role:** cualquier dato que sea una dirección, identificador técnico o valor copiable (BSSID, MAC, IP, SSID, puertos). Nunca se usa para prosa ni para labels.

### Type Scale

| Role | Family | Weight | Size | Line Height | Letter Spacing | Token |
|------|--------|--------|------|-------------|----------------|-------|
| caption | sohne-var | 300 | 12px | 1.45 | -0.12px | `--text-caption` |
| mono-sm | jetbrains-mono | 400 | 12px | 1.4 | 0 | `--text-mono-sm` |
| mono | jetbrains-mono | 400 | 13px | 1.4 | 0 | `--text-mono` |
| body-sm | sohne-var | 300 | 14px | 1.4 | -0.14px | `--text-body-sm` |
| body | sohne-var | 300 | 16px | 1.2 | -0.16px | `--text-body` |
| body-lg | sohne-var | 300 | 20px | 1.4 | -0.2px | `--text-body-lg` |
| subheading | sohne-var | 300 | 22px | 1.1 | -0.22px | `--text-subheading` |
| heading-sm | sohne-var | 300 | 26px | 1.12 | -0.26px | `--text-heading-sm` |
| heading | sohne-var | 300 | 32px | 1.1 | -0.64px | `--text-heading` |
| stat | sohne-var | 300 | 48px | 1.03 | -0.96px | `--text-stat` |

## Tokens — Spacing & Shapes

**Base unit:** 8px
**Density:** comfortable (con opción "compact" para la tabla de redes si hay muchas filas — ver nota en el componente de tabla)

### Spacing Scale

| Name | Value | Token |
|------|-------|-------|
| 8 | 8px | `--spacing-8` |
| 16 | 16px | `--spacing-16` |
| 24 | 24px | `--spacing-24` |
| 32 | 32px | `--spacing-32` |
| 40 | 40px | `--spacing-40` |
| 48 | 48px | `--spacing-48` |
| 64 | 64px | `--spacing-64` |

### Border Radius

| Element | Value |
|---------|-------|
| tags / badges | 9999px |
| cards | 8px |
| inputs | 6px |
| buttons | 6px |

*(Nota: se subió ligeramente de 4px a 6-8px respecto al original: sobre fondo oscuro, los radios muy cerrados se ven más duros; 6-8px mantiene el aire "profesional, no juguetón" pero suaviza mejor sobre superficies oscuras.)*

### Layout

- **Page max-width:** 1200px
- **Section gap:** 64px
- **Card padding:** 24px
- **Element gap:** 8px
- **Sidebar width** (si se usa navegación lateral): 240px

## Components

### Primary Filled Button
**Role:** Acción principal — "Actualizar escaneo", "Iniciar monitoreo de tráfico"

Fondo `--color-indigo-ink`, texto `--color-text-primary` casi blanco, radio 6px, padding `12px 20px`. Tipografía sohne-var 400 a 14px. Hover: fondo `--color-indigo-hover`. Sin sombra; el cambio de tono es la única señal de interacción.

### Ghost Outline Button
**Role:** Acción secundaria — "Cancelar", "Ver detalles"

Fondo transparente, texto `--color-indigo-ink`, borde 1px `--color-indigo-border`, radio 6px, padding `11px 20px`. Mismo spec tipográfico que el botón primario.

### Danger Button
**Role:** Acción destructiva o de alto impacto — "Iniciar interceptación de tráfico" (el botón que dispara el ARP spoofing)

Fondo transparente, texto `--color-risk`, borde 1px en `--color-risk` al 40% de opacidad, radio 6px. Al hacer hover, fondo pasa a `--color-risk-wash`. Este botón es el único lugar donde el rojo semántico se usa en un botón, precisamente porque la acción conlleva riesgo real (interceptar tráfico de otros), y debe sentirse distinto a cualquier otro botón de la interfaz.

### Status Badge
**Role:** Indicador de estado de una red o dispositivo — "segura", "precaución", "riesgo", "oculta"

Pastilla (`border-radius: 9999px`), padding `4px 12px`, tipografía sohne-var 400 a 12px, mayúsculas, letter-spacing +0.04em (único lugar con tracking positivo, para que el badge se lea como una etiqueta, no como prosa). Color de texto y fondo según estado:
- Segura: texto `--color-safe`, fondo `--color-safe-wash`
- Precaución: texto `--color-caution`, fondo `--color-caution-wash`
- Riesgo: texto `--color-risk`, fondo `--color-risk-wash`
- Oculta/neutral: texto `--color-neutral`, fondo `--color-neutral-wash`

### Data Table Row
**Role:** Fila de la tabla de redes o dispositivos

Fondo `--color-surface`, borde inferior 1px `--color-border-soft` (nunca bordes completos alrededor de cada celda). Borde izquierdo de 3px con el color semántico del estado de esa fila (verde/ámbar/rojo/gris) — es la señal visual más rápida de escanear al mirar la tabla completa de arriba a abajo. Celdas de SSID/BSSID/MAC/IP en `--text-mono`; el resto en `--text-body-sm`. Padding vertical 12px, horizontal 16px. Hover: fondo `--color-surface-raised`.

*Modo compact (si la tabla tiene muchas filas, ej. 20+ redes): reduce el padding vertical a 8px y el tamaño de fuente a `--text-mono-sm` / `--text-caption`.*

### Stat Block
**Role:** Resumen numérico — "25 segura · 1 precaución · 0 riesgo"

Número en `--text-stat` (48px, weight 300) con el color semántico correspondiente, label debajo en `--text-body-sm` color `--color-text-secondary`. Se usan en línea, no apilados verticalmente, para el resumen superior del dashboard (igual que el resumen final de la CLI).

### Section Heading Block
**Role:** Título de cada sección del dashboard — "Redes WiFi", "Dispositivos", "Tráfico en vivo"

`--text-heading` (32px, weight 300, `--color-text-primary`), seguido de un párrafo de apoyo opcional en `--color-text-secondary` a `--text-body`. Gap de 16px entre título y párrafo. Gap de 8px entre heading y la fila de acciones (botones) de esa sección.

### Confirmation Dialog (modal)
**Role:** Confirmaciones de acciones sensibles — igual que los prompts "s/N" de la CLI, pero en web

Fondo `--color-surface-raised` sobre overlay oscuro semitransparente (`rgba(10, 14, 23, 0.7)`), radio 8px, padding 32px, max-width 440px. Título en `--text-heading-sm`, cuerpo en `--text-body` color `--color-text-secondary`. Para confirmaciones de riesgo (iniciar tráfico), el ícono/acento del modal usa `--color-risk`; para confirmaciones normales (confiar en una red), usa `--color-indigo-ink`. Siempre dos botones: Ghost (cancelar) + Primary o Danger (confirmar), en ese orden, cancelar a la izquierda.

### Live Indicator
**Role:** Mostrar que una vista se está actualizando en tiempo real (tabla de tráfico en vivo)

Punto de 8px de diámetro con animación de pulso suave (`opacity` 1 → 0.4 → 1, 2s, ease-in-out, infinito), color `--color-safe` si el monitoreo está activo, `--color-neutral` si está detenido. Acompañado de texto `--text-caption` ("En vivo" / "Detenido").

### Section Divider
**Role:** Separación entre secciones mayores del dashboard

Línea de 1px sólida en `--color-border`, ancho completo del contenido. Sin elementos decorativos.

### Navigation (sidebar o top bar)
**Role:** Navegación entre Redes / Dispositivos / Tráfico / Confiables

Fondo `--color-surface`, borde derecho o inferior 1px `--color-border`. Ítem activo: texto `--color-indigo-ink`, fondo `--color-indigo-wash`, radio 6px. Ítems inactivos: texto `--color-text-secondary`, sohne-var 400 a 14px.

## Do's and Don'ts

### Do
- Usar `--color-indigo-ink` exclusivamente para acciones genéricas (botones, links, navegación activa, foco) — nunca para indicar un estado de seguridad
- Reservar verde/ámbar/rojo/gris exclusivamente para estados de riesgo (badges, bordes de fila, el botón de iniciar tráfico) — nunca como color decorativo o de marca
- Usar `--text-mono` (JetBrains Mono) para toda MAC, BSSID, IP, SSID y cualquier dato técnico/copiable
- Aplicar `font-feature-settings: "tnum" on` en cualquier tabla con números (canal, señal, porcentaje, KB) para que las columnas alineen
- Mantener weight 300 en toda la tipografía sohne-var, incluso en los stats grandes — el "whisper-weight" es la firma visual, y funciona igual de bien en oscuro que en claro
- Separar secciones con `--color-border` de 1px y 64px de espacio vertical, no con sombras ni cambios de fondo

### Don't
- No usar rojo/verde/ámbar en elementos que no comuniquen un estado real de seguridad (evita decorar botones normales con estos colores "porque se ven bien")
- No usar la tipografía monoespaciada para prosa, labels o botones — solo para datos técnicos
- No usar sombras en ningún componente; la profundidad viene de `--color-surface` vs `--color-surface-raised`, nunca de `box-shadow`
- No mezclar el indigo con los colores semánticos en un mismo elemento (ej. un botón no puede tener borde indigo y texto rojo)
- No usar radios mayores a 8px (se perdería el carácter "panel técnico") ni menores a 6px (se vería demasiado duro en oscuro)

## Quick Start

### CSS Custom Properties

```css
:root {
  color-scheme: dark;

  /* Superficies */
  --color-canvas: #0a0e17;
  --color-surface: #11151f;
  --color-surface-raised: #171c28;
  --color-border: #232a38;
  --color-border-soft: #1a1f2b;

  /* Texto */
  --color-text-primary: #e8ecf5;
  --color-text-secondary: #8b96ab;
  --color-text-muted: #5b6577;

  /* Acento */
  --color-indigo-ink: #6d5bf7;
  --color-indigo-hover: #8a7bff;
  --color-indigo-wash: #1a1733;
  --color-indigo-border: #3b3570;

  /* Semántico */
  --color-safe: #34d399;
  --color-safe-wash: #0d2420;
  --color-caution: #fbbf24;
  --color-caution-wash: #2a2210;
  --color-risk: #f87171;
  --color-risk-wash: #2a1414;
  --color-neutral: #94a3b8;
  --color-neutral-wash: #1c212c;

  /* Tipografía — familias */
  --font-sohne-var: 'sohne-var', 'Inter Tight', ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Consolas, monospace;

  /* Tipografía — escala */
  --text-caption: 12px;  --leading-caption: 1.45;  --tracking-caption: -0.12px;
  --text-mono-sm: 12px;  --leading-mono-sm: 1.4;
  --text-mono: 13px;     --leading-mono: 1.4;
  --text-body-sm: 14px;  --leading-body-sm: 1.4;   --tracking-body-sm: -0.14px;
  --text-body: 16px;     --leading-body: 1.2;      --tracking-body: -0.16px;
  --text-body-lg: 20px;  --leading-body-lg: 1.4;   --tracking-body-lg: -0.2px;
  --text-subheading: 22px; --leading-subheading: 1.1; --tracking-subheading: -0.22px;
  --text-heading-sm: 26px; --leading-heading-sm: 1.12; --tracking-heading-sm: -0.26px;
  --text-heading: 32px;  --leading-heading: 1.1;   --tracking-heading: -0.64px;
  --text-stat: 48px;     --leading-stat: 1.03;     --tracking-stat: -0.96px;

  /* Pesos */
  --font-weight-light: 300;
  --font-weight-regular: 400;

  /* Espaciado */
  --spacing-8: 8px;
  --spacing-16: 16px;
  --spacing-24: 24px;
  --spacing-32: 32px;
  --spacing-40: 40px;
  --spacing-48: 48px;
  --spacing-64: 64px;

  /* Layout */
  --page-max-width: 1200px;
  --section-gap: 64px;
  --card-padding: 24px;
  --element-gap: 8px;
  --sidebar-width: 240px;

  /* Radios */
  --radius-tags: 9999px;
  --radius-cards: 8px;
  --radius-inputs: 6px;
  --radius-buttons: 6px;
}

body {
  background: var(--color-canvas);
  color: var(--color-text-primary);
  font-family: var(--font-sohne-var);
  font-weight: var(--font-weight-light);
  font-feature-settings: "ss01" on, "tnum" on;
}

.mono {
  font-family: var(--font-mono);
  font-feature-settings: "tnum" on;
}
```