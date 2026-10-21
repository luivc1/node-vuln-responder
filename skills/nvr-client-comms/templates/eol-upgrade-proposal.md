# End-of-life upgrade proposal

## EN
**Subject:** Action needed: {{site}} runs an unsupported Node.js version

Hi {{client_name}},

{{site}} runs Node.js {{current_version}}, which reached end of life and will **not**
receive fixes from the {{RELEASE_DATE}} security release (highest severity High).
Fixes were released only for Node.js {{FIXED_VERSIONS}}.

What we did today to reduce risk: {{containment_applied}}. This lowers exposure but
does not remove it.

Recommended: move the app to Node.js {{target_branch}}.
- Steps: staging branch, dependency and native-addon check, testing,
  deploy, 48-hour rollback window.
- Estimated time: {{estimate_time}}. Investment: {{estimate_price}}.
- Possible impacts: {{known_incompatibilities_or_none}}.

Please reply to approve so we can schedule it this week.

{{your_name}}

## ES
**Asunto:** Acción requerida: {{site}} usa una versión de Node.js sin soporte

Hola {{client_name}}:

{{site}} funciona con Node.js {{current_version}}, que llegó al fin de su vida útil y
**no** recibirá las correcciones del release de seguridad del {{RELEASE_DATE}}
(severidad máxima Alta). Solo se publicaron para Node.js {{FIXED_VERSIONS}}.

Lo que hicimos hoy para reducir el riesgo: {{containment_applied}}. Esto reduce la
exposición, pero no la elimina.

Recomendación: migrar la aplicación a Node.js {{target_branch}}.
- Pasos: rama de prueba (staging), revisión de dependencias y módulos nativos,
  pruebas, despliegue y 48 horas de respaldo para revertir.
- Tiempo estimado: {{estimate_time}}. Inversión: {{estimate_price}}.
- Posibles impactos: {{known_incompatibilities_or_none}}.

Favor de responder con su aprobación para programarlo esta semana.

{{your_name}}
