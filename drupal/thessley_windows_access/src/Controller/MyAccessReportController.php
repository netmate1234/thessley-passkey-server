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
    return $this->buildForCurrentUser();
  }

  /** Builds the signed-in user's report for use on the landing page too. */
  public function buildForCurrentUser(): array {
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

    $account_cards = [];
    foreach ($accounts as $account) {
      $groups = array_values(array_unique($account['groups']));
      $account_cards[] = [
        'title' => $account['computer'] . ' · ' . $account['username'],
        'fields' => [
          $this->t('Status') => $account['status'],
          $this->t('Active phones') => (string) $account['phones'],
          $this->t('Last PC report') => $account['last_seen'],
          $this->t('Reported Windows groups') => $groups ? implode(', ', $groups) : (string) $this->t('No group report yet'),
        ],
      ];
    }

    $activity_rows = [];
    foreach ($this->store->recentLoginDecisions($uid, 20) as $event) {
      $details = json_decode((string) $event->details, TRUE);
      $details = is_array($details) ? $details : [];
      $decision = $event->event === 'phone_login_approved'
        ? $this->t('Phone approved')
        : $this->t('Phone denied');
      $activity_cards[] = [
        'title' => \Drupal::service('date.formatter')->format((int) $event->created, 'short') . ' · ' . (string) ($details['computer'] ?? $this->t('Unknown computer')),
        'fields' => [
          $this->t('Windows account') => (string) ($details['username'] ?? ''),
          $this->t('Phone') => (string) ($details['phone'] ?? ''),
          $this->t('Phone decision') => (string) $decision,
        ],
      ];
    }

    $roles = $this->currentUser()->getRoles(TRUE);
    $role_labels = [];
    $access_rows = [];
    $role_entities = $this->entityTypeManager()->getStorage('user_role')->loadMultiple($roles);
    $resources = [];
    foreach ($this->store->resources() as $resource) {
      $resources[(int) $resource->id] = (string) $resource->label;
    }
    $action_labels = [
      'windows.login' => $this->t('Windows sign-in'),
      'windows.local_admin' => $this->t('Windows local administrator'),
      'windows.remote_desktop' => $this->t('Remote Desktop Users'),
      'windows.remote_management' => $this->t('Remote Management Users'),
      'windows.event_log_readers' => $this->t('Event Log Readers'),
      'connect' => $this->t('Connect'),
      'download' => $this->t('Download'),
      'access' => $this->t('Access'),
    ];
    foreach ($role_entities as $role_id => $role) {
      $role_labels[] = $role->label();
      foreach ($this->store->roleGrantValues((string) $role_id) as $grant) {
        [$resource_id, $action] = array_pad(explode(':', $grant, 2), 2, '');
        $resource_id = (int) $resource_id;
        if (isset($resources[$resource_id], $action_labels[$action])) {
          $access_cards[] = [
            'title' => $resources[$resource_id],
            'fields' => [
              $this->t('Group') => $role->label(),
              $this->t('Right') => (string) $action_labels[$action],
            ],
          ];
        }
      }
    }

    return [
      '#cache' => ['max-age' => 0],
      'intro' => [
        '#markup' => $this->t('This private report shows only access data linked to your Drupal sign-in: your groups and their rights, Windows accounts, phone count, and PC-reported group inventory.'),
      ],
      'roles_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Your Drupal groups'),
      ],
      'roles' => [
        '#plain_text' => $role_labels ? implode(', ', $role_labels) : (string) $this->t('No additional groups'),
      ],
      'rights_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Your access rights'),
      ],
      'rights' => $this->buildCards($access_cards ?? [], $this->t('No Windows or resource rights are assigned to your groups.')),
      'accounts_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Your Windows accounts'),
      ],
      'accounts' => $this->buildCards($account_cards, $this->t('No Windows accounts are linked to your Drupal user.')),
      'activity_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Recent phone login activity'),
      ],
      'activity_note' => [
        '#type' => 'item',
        '#markup' => $this->t('These entries show whether the phone approved or denied a request. They do not confirm that Windows completed sign-in.'),
      ],
      'activity' => $this->buildCards($activity_cards ?? [], $this->t('No phone login decisions have been recorded yet.')),
    ];
  }

  /** Builds mobile-friendly cards with semantic label/value pairs. */
  private function buildCards(array $records, string $empty_message): array {
    $build = [
      '#type' => 'container',
      '#attributes' => ['class' => ['thessley-record-grid']],
    ];
    if (!$records) {
      $build['empty'] = ['#type' => 'item', '#markup' => $empty_message];
      return $build;
    }
    foreach ($records as $index => $record) {
      $card = [
        '#type' => 'container',
        '#attributes' => ['class' => ['thessley-record-card']],
        'title' => [
          '#type' => 'container',
          '#attributes' => ['class' => ['thessley-record-card-title']],
          'text' => ['#plain_text' => $record['title']],
        ],
        'fields' => ['#type' => 'container', '#attributes' => ['class' => ['thessley-record-fields']]],
      ];
      $field_index = 0;
      foreach ($record['fields'] as $label => $value) {
        $card['fields']['field_' . $field_index++] = [
          '#type' => 'container',
          '#attributes' => ['class' => ['thessley-record-field']],
          'label' => ['#plain_text' => (string) $label],
          'value' => ['#plain_text' => (string) $value],
        ];
      }
      $build['card_' . $index] = $card;
    }
    return $build;
  }

}
