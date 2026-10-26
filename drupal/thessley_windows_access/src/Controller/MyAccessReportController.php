<?php

namespace Drupal\thessley_windows_access\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\thessley_windows_access\WindowsAccessStore;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Read-only Windows Access report scoped to the signed-in Drupal account.
 */
final class MyAccessReportController extends ControllerBase {

  public function __construct(protected WindowsAccessStore $store) {}

  public static function create(ContainerInterface $container): static {
    return new static($container->get('thessley_windows_access.store'));
  }

  public function overview(): array {
    $uid = (int) $this->currentUser()->id();
    $accounts = [];
    foreach ($this->store->accountInventoryForUser($uid) as $item) {
      $id = (int) $item->id;
      if (!isset($accounts[$id])) {
        $phones = $this->store->phonesForAccount($id);
        $active_phones = 0;
        foreach ($phones as $phone) {
          if ($phone->revoked === NULL && $item->revoked === NULL) {
            $active_phones++;
          }
        }
        $accounts[$id] = [
          'computer' => (string) ($item->hostname ?: $item->machine_id),
          'username' => (string) $item->username,
          'status' => $item->revoked !== NULL ? $this->t('Revoked') : (string) $item->status,
          'last_seen' => $item->last_seen
            ? \Drupal::service('date.formatter')->format((int) $item->last_seen, 'short')
            : $this->t('Not reported yet'),
          'phones' => $active_phones,
          'groups' => [],
        ];
      }
      if ($item->group_name !== NULL) {
        $accounts[$id]['groups'][] = (string) $item->group_name;
      }
    }

    $rows = [];
    foreach ($accounts as $account) {
      $groups = array_values(array_unique($account['groups']));
      $rows[] = [
        ['data' => ['#plain_text' => $account['computer']]],
        ['data' => ['#plain_text' => $account['username']]],
        ['data' => ['#plain_text' => $account['status']]],
        ['data' => ['#plain_text' => (string) $account['phones']]],
        ['data' => ['#plain_text' => $account['last_seen']]],
        ['data' => ['#plain_text' => $groups ? implode(', ', $groups) : (string) $this->t('No group report yet')]],
      ];
    }

    $roles = $this->currentUser()->getRoles(TRUE);
    $role_labels = [];
    foreach ($this->entityTypeManager()->getStorage('user_role')->loadMultiple($roles) as $role) {
      $role_labels[] = $role->label();
    }

    return [
      '#cache' => ['max-age' => 0],
      'intro' => [
        '#markup' => $this->t('This private report shows only Windows accounts linked to your Drupal user, the phone credentials attached to those accounts, and group inventory last reported by each PC.'),
      ],
      'roles_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Your Drupal groups'),
      ],
      'roles' => [
        '#plain_text' => $role_labels ? implode(', ', $role_labels) : (string) $this->t('No additional groups'),
      ],
      'accounts_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Your Windows accounts'),
      ],
      'accounts' => [
        '#type' => 'table',
        '#header' => [
          $this->t('Computer'),
          $this->t('Windows account'),
          $this->t('Status'),
          $this->t('Active phones'),
          $this->t('Last PC report'),
          $this->t('Reported Windows groups'),
        ],
        '#rows' => $rows,
        '#empty' => $this->t('No Windows accounts are linked to your Drupal user.'),
        '#attributes' => ['class' => ['responsive-enabled']],
      ],
    ];
  }

}
