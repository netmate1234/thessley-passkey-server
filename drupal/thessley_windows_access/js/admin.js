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

  Drupal.behaviors.thessleyWindowsAccessGroups = {
    attach: function (context) {
      once('thessley-windows-access-groups', 'form.thessley-policy-editor', context).forEach(function (editor) {
        var announcement = editor.querySelector('[data-thessley-announcement]');

        editor.querySelectorAll('[data-thessley-uid]').forEach(function (person) {
          person.addEventListener('dragstart', function (event) {
            event.dataTransfer.effectAllowed = 'copy';
            event.dataTransfer.setData('text/plain', person.getAttribute('data-thessley-uid'));
            person.classList.add('is-dragging');
          });
          person.addEventListener('dragend', function () {
            person.classList.remove('is-dragging');
          });
        });

        editor.querySelectorAll('[data-thessley-role]').forEach(function (group) {
          group.addEventListener('dragover', function (event) {
            if (Array.prototype.indexOf.call(event.dataTransfer.types, 'text/plain') !== -1) {
              event.preventDefault();
              event.dataTransfer.dropEffect = 'copy';
              group.classList.add('is-drop-target');
            }
          });
          group.addEventListener('dragleave', function (event) {
            if (!group.contains(event.relatedTarget)) {
              group.classList.remove('is-drop-target');
            }
          });
          group.addEventListener('drop', function (event) {
            event.preventDefault();
            group.classList.remove('is-drop-target');
            var uid = event.dataTransfer.getData('text/plain');
            var checkboxes = group.querySelectorAll('input[type="checkbox"]');
            var match = Array.prototype.find.call(checkboxes, function (checkbox) {
              return checkbox.value === uid;
            });
            if (match && !match.checked) {
              match.checked = true;
              match.dispatchEvent(new Event('change', { bubbles: true }));
              if (announcement) {
                announcement.textContent = Drupal.t('Person added to @group.', {'@group': group.querySelector('legend').textContent.trim()});
              }
            }
          });
        });

        editor.querySelectorAll('[data-thessley-grant]').forEach(function (right) {
          right.addEventListener('dragstart', function (event) {
            event.dataTransfer.effectAllowed = 'copy';
            event.dataTransfer.setData('application/x-thessley-grant', right.getAttribute('data-thessley-grant'));
            right.classList.add('is-dragging');
          });
          right.addEventListener('dragend', function () {
            right.classList.remove('is-dragging');
          });
        });

        editor.querySelectorAll('[data-thessley-grant-role]').forEach(function (group) {
          group.addEventListener('dragover', function (event) {
            if (Array.prototype.indexOf.call(event.dataTransfer.types, 'application/x-thessley-grant') !== -1) {
              event.preventDefault();
              event.dataTransfer.dropEffect = 'copy';
              group.classList.add('is-grant-drop-target');
            }
          });
          group.addEventListener('dragleave', function (event) {
            if (!group.contains(event.relatedTarget)) {
              group.classList.remove('is-grant-drop-target');
            }
          });
          group.addEventListener('drop', function (event) {
            var grantId = event.dataTransfer.getData('application/x-thessley-grant');
            if (!grantId) {
              return;
            }
            event.preventDefault();
            group.classList.remove('is-grant-drop-target');
            var checkboxes = group.querySelectorAll('input[type="checkbox"]');
            var match = Array.prototype.find.call(checkboxes, function (checkbox) {
              return checkbox.value === grantId;
            });
            if (match && !match.checked) {
              match.checked = true;
              match.dispatchEvent(new Event('change', { bubbles: true }));
              if (announcement) {
                var heading = group.querySelector('summary');
                announcement.textContent = Drupal.t('Resource right added to @group.', {'@group': heading ? heading.textContent.trim() : Drupal.t('group')});
              }
            }
          });
        });
      });
    }
  };
})(Drupal, once, drupalSettings);
