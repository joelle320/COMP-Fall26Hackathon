window.onload = function () {
  window.ui = SwaggerUIBundle({
    url: "/api/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    persistAuthorization: false,
    validatorUrl: null,
    presets: [SwaggerUIBundle.presets.apis],
  });
};
