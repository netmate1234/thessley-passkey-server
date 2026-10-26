<?php

namespace Drupal\thessley_windows_access\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Link;
use Drupal\Core\Url;
use Drupal\thessley_windows_access\WindowsAccessStore;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Read-only Admin view of Windows accounts and PC-reported group inventory.
 */
final class InventoryController extends ControllerBase {

  public function __construct(protected WindowsAccessStore $store) {}

  public static function create(ContainerInterface $container): static {
    return new static($container->get('thessley_windows_access.store'));
  }

  public function overview(): array {
    $accounts = [];
    foreach ($this->store->accountInventory() as $item) {
      $id = (int) $item->id;
      if (!isset($accounts[$id])) {
        $identity = $this->entityTypeManager()->getStorage('user')->load((int) $item->uid);
        $accounts[$id] = [
          'machine' => (string) $item->hostname . ' (' . (string) $item->machine_id . ')',
          'username' => (string) $item->username,
          'identity' => $identity ? $identity->getAccountName() : $this->t('Missing Drupal user'),
          'status' => $item->revoked !== NULL ? $this->t('Revoked') : (string) $item->status,
          'last_seen' => $item->last_seen ? \Drupal::service('date.formatter')->format((int) $item->last_seen, 'short') : $this->t('Never'),
          'groups' => [],
          'phones' => [],
        ];
        foreach ($this->store->phonesForAccount($id) as $phone) {
          $label = (string) $phone->label . ' · ' . substr((string) $phone->credential_id, 0, 10) . '…';
          $entry = [
            '#type' => 'container',
            'label' => ['#plain_text' => $label . ($phone->revoked !== NULL ? ' — ' . (string) $this->t('revoked') : '')],
          ];
          if ($phone->revoked === NULL && $item->revoked === NULL) {
            $entry['revoke'] = Link::fromTextAndUrl(
              $this->t('Revoke'),
              Url::fromRoute('thessley_windows_access.revoke_phone', [
                'account_id' => $id,
                'phone_id' => (int) $phone->id,
              ]),
            )->toRenderable();
          }
          $accounts[$id]['phones'][] = $entry;
        }
      }
      if ($item->group_name !== NULL) {
        $accounts[$id]['groups'][] = (string) $item->group_name . ' · ' . substr((string) $item->group_sid_hash, 0, 12);
      }
    }

    $rows = [];
    foreach ($accounts as $account) {
      $rows[] = [
        ['data' => ['#plain_text' => $account['machine']]],
        ['data' => ['#plain_text' => $account['username']]],
        ['data' => ['#plain_text' => (string) $account['identity']]],
        ['data' => ['#plain_text' => (string) $account['status']]],
        ['data' => ['#plain_text' => (string) $account['last_seen']]],
        $account['phones'] ? ['data' => ['#theme' => 'item_list', '#items' => $account['phones']]] : ['data' => ['#plain_text' => (string) $this->t('No enrolled phone')]],
        ['data' => ['#plain_text' => $account['groups'] ? implode("\n", $account['groups']) : (string) $this->t('No group report yet')]],
      ];
    }

    return [
      '#cache' => ['max-age' => 0],
      '#attached' => ['library' => ['thessley_windows_access/admin']],
      'actions' => [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-windows-access-actions']],
        'enroll' => Link::createFromRoute($this->t('Enroll a Windows account'), 'thessley_windows_access.enroll')->toRenderable(),
        'groups' => Link::createFromRoute($this->t('Manage groups and access'), 'thessley_windows_access.policy')->toRenderable(),
        'settings' => Link::createFromRoute($this->t('Server settings'), 'thessley_windows_access.admin')->toRenderable(),
      ],
      'intro' => [
        '#markup' => $this->t('PC-reported Windows groups are inventory. Drupal roles and resource grants control Thessley access. The endpoint agent changes membership only in explicitly granted supported groups: Administrators, Remote Desktop Users, Event Log Readers, and Remote Management Users.'),
      ],
      'inventory' => [
        '#type' => 'table',
        '#header' => [
          $this->t('Computer'),
          $this->t('Windows account'),
          $this->t('Drupal user'),
          $this->t('Binding'),
          $this->t('Last report'),
          $this->t('Phone credentials'),
          $this->t('Reported Windows groups'),
        ],
        '#rows' => $rows,
        '#empty' => $this->t('No Windows accounts have been enrolled.'),
        '#attributes' => ['class' => ['responsive-enabled']],
      ],
    ];
  }

}
