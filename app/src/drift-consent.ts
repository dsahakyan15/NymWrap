// Enabling automation is a separate, explicit decision, independent of mode selection.
export function createAiWebConsent(enabled: unknown = false) {
  const label = document.createElement("label"), input = document.createElement("input");
  input.type = "checkbox"; input.id = "ai-web-consent"; input.checked = enabled === true;
  label.append(input, document.createTextNode(" Я явно разрешаю проверку автоматизации ИИ-чатов на локальных синтетических страницах. Предупреждение: автоматизация настоящих веб-чатов может нарушать условия сервиса и привести к блокировке аккаунта. Доступ к настоящим чатам эта настройка не включает."));
  return { label, input };
}
