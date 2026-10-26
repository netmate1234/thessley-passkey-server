(function (Drupal, once, drupalSettings) {
  'use strict';

  Drupal.behaviors.thessleyWindowsAccessQr = {
    attach: function (context) {
      var cfg = drupalSettings.thessleyWindowsAccess || {};
      if (!cfg.appLink || !window.ThessleyQR) {
        return;
      }
      once('thessley-windows-access-qr', '#thessley-windows-enrollment-qr', context).forEach(function (el) {
        window.ThessleyQR.render(el, cfg.appLink, 360);
      });
    }
  };
})(Drupal, once, drupalSettings);
