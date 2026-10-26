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

    $activity_rows = [];
    foreach ($this->store->recentLoginDecisions($uid, 20) as $event) {
      $details = json_decode((string) $event->details, TRUE);
      $details = is_array($details) ? $details : [];
      $decision = $event->event === 'phone_login_approved'
        ? $this->t('Phone approved')
        : $this->t('Phone denied');
      $activity_rows[] = [
        ['data' => ['#plain_text' => \Drupal::service('date.formatter')->format((int) $event->created, 'short')]],
        ['data' => ['#plain_text' => (string) ($details['computer'] ?? $this->t('Unknown computer'))]],
        ['data' => ['#plain_text' => (string) ($details['username'] ?? '')]],
        ['data' => ['#plain_text' => (string) ($details['phone'] ?? '')]],
        ['data' => ['#plain_text' => (string) $decision]],
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
          $access_rows[] = [
            ['data' => ['#plain_text' => $role->label()]],
            ['data' => ['#plain_text' => $resources[$resource_id]]],
            ['data' => ['#plain_text' => (string) $action_labels[$action]]],
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
      'rights' => [
        '#type' => 'table',
        '#header' => [$this->t('Group'), $this->t('Computer or resource'), $this->t('Right')],
        '#rows' => $access_rows,
        '#empty' => $this->t('No Windows or resource rights are assigned to your groups.'),
        '#attributes' => ['class' => ['responsive-enabled']],
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
      'activity_title' => [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#value' => $this->t('Recent phone login activity'),
      ],
      'activity_note' => [
        '#type' => 'item',
        '#markup' => $this->t('These entries show whether the phone approved or denied a request. They do not confirm that Windows completed sign-in.'),
      ],
      'activity' => [
        '#type' => 'table',
        '#header' => [
          $this->t('Time'),
          $this->t('Computer'),
          $this->t('Windows account'),
          $this->t('Phone'),
          $this->t('Phone decision'),
        ],
        '#rows' => $activity_rows,
        '#empty' => $this->t('No phone login decisions have been recorded yet.'),
        '#attributes' => ['class' => ['responsive-enabled']],
      ],
    ];
  }

}
