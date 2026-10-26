<?php

namespace Drupal\thessley_windows_access\Form;

use Drupal\Core\Form\ConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Url;
use Drupal\thessley_windows_access\WindowsAccessStore;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Confirmation form for revoking a Windows account phone credential.
 */
final class RevokePhoneForm extends ConfirmFormBase {

  public function __construct(
    protected WindowsAccessStore $store,
    protected RouteMatchInterface $routeMatchService,
  ) {}

  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('thessley_windows_access.store'),
      $container->get('current_route_match'),
    );
  }

  public function getFormId(): string {
    return 'thessley_windows_access_revoke_phone';
  }

  public function getQuestion(): string {
    $phone = $this->phone();
    return (string) $this->t('Revoke phone “@label”?', ['@label' => $phone->label]);
  }

  public function getDescription(): string {
    return (string) $this->t('This phone will no longer be able to approve sign-ins for this Windows account. Other enrolled phones remain active.');
  }

  public function getCancelUrl(): Url {
    return Url::fromRoute('thessley_windows_access.inventory');
  }

  public function getConfirmText(): string {
    return (string) $this->t('Revoke phone');
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $phone = $this->phone();
    $form = parent::buildForm($form, $form_state);
    $form['credential'] = [
      '#type' => 'item',
      '#title' => $this->t('Credential'),
      '#plain_text' => substr((string) $phone->credential_id, 0, 12) . '…',
    ];
    return $form;
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $account_id = (int) $this->routeMatchService->getParameter('account_id');
    $phone_id = (int) $this->routeMatchService->getParameter('phone_id');
    $actor_uid = (int) $this->currentUser()->id();
    if ($this->store->revokePhone($account_id, $phone_id, $actor_uid)) {
      $this->messenger()->addStatus($this->t('The phone credential was revoked.'));
    }
    else {
      $this->messenger()->addWarning($this->t('That phone credential was already revoked.'));
    }
    $form_state->setRedirect('thessley_windows_access.inventory');
  }

  private function phone(): object {
    $account_id = (int) $this->routeMatchService->getParameter('account_id');
    $phone_id = (int) $this->routeMatchService->getParameter('phone_id');
    foreach ($this->store->phonesForAccount($account_id) as $phone) {
      if ((int) $phone->id === $phone_id && $phone->revoked === NULL) {
        return $phone;
      }
    }
    throw new NotFoundHttpException();
  }

}
