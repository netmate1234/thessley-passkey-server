<?php

namespace Drupal\thessley_windows_access\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Link;

/**
 * Windows Access landing page for Drupal administrators.
 */
final class AdminLandingController extends ControllerBase {

  public function overview(): array {
    $items = [
      [
        'title' => $this->t('Accounts and computers'),
        'description' => $this->t('Review Windows account bindings, enrolled phones, computer reports, and revoke a phone credential.'),
        'route' => 'thessley_windows_access.inventory',
        'link' => $this->t('Open account inventory'),
      ],
      [
        'title' => $this->t('Enroll a Windows account'),
        'description' => $this->t('Link one Windows account on one computer to a Drupal user and enroll its first approval phone.'),
        'route' => 'thessley_windows_access.enroll',
        'link' => $this->t('Start enrollment'),
      ],
      [
        'title' => $this->t('Groups and access rights'),
        'description' => $this->t('Assign Drupal users to access groups and choose which computers and resources each group can use.'),
        'route' => 'thessley_windows_access.policy',
        'link' => $this->t('Manage groups and rights'),
      ],
      [
        'title' => $this->t('Server settings'),
        'description' => $this->t('Set the HTTPS PAM server origin and the certificate fingerprint trusted by the phone app.'),
        'route' => 'thessley_windows_access.admin',
        'link' => $this->t('Configure the server'),
      ],
    ];

    $cards = [];
    foreach ($items as $index => $item) {
      $cards['item_' . $index] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-windows-access-card']],
        'title' => [
          '#type' => 'html_tag',
          '#tag' => 'h2',
          '#value' => $item['title'],
        ],
        'description' => [
          '#type' => 'item',
          '#markup' => $item['description'],
        ],
        'link' => Link::createFromRoute($item['link'], $item['route'])->toRenderable(),
      ];
    }

    return [
      '#attached' => ['library' => ['thessley_windows_access/admin']],
      'intro' => [
        '#type' => 'item',
        '#markup' => $this->t('Manage Windows login and resource access from here. Drupal roles act as groups; accounts inherit the groups assigned to their linked Drupal user.'),
      ],
      'cards' => [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-windows-access-dashboard']],
        'items' => $cards,
      ],
    ];
  }

}
