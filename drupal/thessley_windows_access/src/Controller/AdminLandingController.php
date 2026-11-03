<?php

namespace Drupal\thessley_windows_access\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Link;
use Drupal\thessley_windows_access\WindowsAccessStore;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Windows Access landing page for Drupal administrators.
 */
final class AdminLandingController extends ControllerBase {

  public function __construct(protected WindowsAccessStore $store) {}

  public static function create(ContainerInterface $container): static {
    return new static($container->get('thessley_windows_access.store'));
  }

  public function overview(): array {
    $items = [
      [
        'title' => $this->t('Windows accounts and sync report'),
        'description' => $this->t('Review linked Windows accounts, last check-in, reported local groups, and enrolled phones. Revoke a phone credential when needed.'),
        'route' => 'thessley_windows_access.inventory',
        'link' => $this->t('Open Windows report'),
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

    $build = [
      '#attached' => ['library' => ['thessley_windows_access/admin']],
      'intro' => [
        '#type' => 'item',
        '#markup' => $this->t('Windows Access tools are listed below. Sign in with a Windows Access administrator account to manage them. Drupal roles act as groups; each linked Windows account inherits its user’s roles. Enrolled PCs report account group membership and receive policy updates when the Windows agent is installed and running.'),
      ],
      'cards' => [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-windows-access-dashboard']],
        'items' => $cards,
      ],
    ];

    if ($this->currentUser()->isAuthenticated()) {
      $build['my_report'] = [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-windows-access-my-report']],
        'title' => [
          '#type' => 'html_tag',
          '#tag' => 'h2',
          '#value' => $this->t('Your linked data'),
        ],
        'report' => (new MyAccessReportController($this->store))->buildForCurrentUser(),
      ];
    }

    return $build;
  }

}
