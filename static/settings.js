function debounce(func, delay) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), delay);
    };
}

document.addEventListener('DOMContentLoaded', function() {
    const twilioSettingsForm = document.getElementById('twilio-settings-form');
    const twilioFeedback = document.getElementById('twilio-feedback');
    const importTwilioHistoryBtn = document.getElementById('import-twilio-history-btn');
    const importHistoryFeedback = document.getElementById('import-history-feedback');
    const recalcBtn = document.getElementById('recalc-last-activity-btn');
    const recalcFeedback = document.getElementById('recalc-feedback');
    const applySheetBtn = document.getElementById('apply-sheet-contacts-btn');
    const applySheetTextarea = document.getElementById('sheet-contacts-input');
    const applySheetFeedback = document.getElementById('apply-sheet-contacts-feedback');

    if (twilioSettingsForm) {
        twilioSettingsForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            twilioFeedback.textContent = ''; // Clear previous messages
            twilioFeedback.style.color = 'black';
            twilioFeedback.textContent = 'Saving...';

            const accountSid = document.getElementById('account_sid').value;
            const authToken = document.getElementById('auth_token').value;
            const phoneNumber = document.getElementById('phone_number').value;

            try {
                const response = await fetch('/api/configure_twilio', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ account_sid: accountSid, auth_token: authToken, phone_number: phoneNumber }),
                });

                const result = await response.json();
                if (response.ok) {
                    twilioFeedback.style.color = 'green';
                    twilioFeedback.textContent = result.message;
                    // Optionally, trigger a refresh of other parts of the UI if needed
                } else {
                    twilioFeedback.style.color = 'red';
                    twilioFeedback.textContent = result.error;
                }
            } catch (error) {
                console.error('Error saving Twilio settings:', error);
                twilioFeedback.style.color = 'red';
                twilioFeedback.textContent = 'An unexpected error occurred.';
            }
        });
    }

    if (importTwilioHistoryBtn) {
        importTwilioHistoryBtn.addEventListener('click', async function() {
            if (!confirm("Importing historical data may take a while and could potentially create new conversations. Do you want to proceed?")) {
                return;
            }
            importHistoryFeedback.textContent = '';
            importHistoryFeedback.style.color = 'black';
            importHistoryFeedback.textContent = 'Importing... This may take a while.';
            
            try {
                const response = await fetch('/api/import_twilio_history', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });
                const result = await response.json();
                if (response.ok) {
                    importHistoryFeedback.style.color = 'green';
                    importHistoryFeedback.textContent = result.message;
                } else {
                    importHistoryFeedback.style.color = 'red';
                    importHistoryFeedback.textContent = result.error;
                }
            } catch (error) {
                console.error('Error importing Twilio history:', error);
                importHistoryFeedback.style.color = 'red';
                importHistoryFeedback.textContent = 'An unexpected error occurred during import.';
            }
        });
    }

    if (recalcBtn) {
        recalcBtn.addEventListener('click', async function() {
            recalcFeedback.textContent = 'Recalculating...';
            recalcFeedback.style.color = 'black';
            try {
                const response = await fetch('/api/recalculate_last_activity', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
                const result = await response.json();
                if (response.ok) {
                    recalcFeedback.style.color = 'green';
                    recalcFeedback.textContent = result.message || 'Recalculated.';
                } else {
                    recalcFeedback.style.color = 'red';
                    recalcFeedback.textContent = result.error || 'Failed to recalculate.';
                }
            } catch (e) {
                console.error('Error recalculating last activity:', e);
                recalcFeedback.style.color = 'red';
                recalcFeedback.textContent = 'An unexpected error occurred.';
            }
        });
    }

    if (applySheetBtn) {
        applySheetBtn.addEventListener('click', async function() {
            applySheetFeedback.style.color = 'black';
            applySheetFeedback.textContent = 'Applying...';
            try {
                let payload;
                const text = (applySheetTextarea.value || '').trim();
                if (!text) {
                    applySheetFeedback.style.color = 'red';
                    applySheetFeedback.textContent = 'Please paste JSON contacts.';
                    return;
                }
                try {
                    payload = JSON.parse(text);
                } catch (e) {
                    applySheetFeedback.style.color = 'red';
                    applySheetFeedback.textContent = 'Invalid JSON.';
                    return;
                }

                const response = await fetch('/api/apply_sheet_contacts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ contacts: payload })
                });
                const result = await response.json();
                if (response.ok) {
                    applySheetFeedback.style.color = 'green';
                    applySheetFeedback.textContent = result.message || 'Applied.';
                } else {
                    applySheetFeedback.style.color = 'red';
                    applySheetFeedback.textContent = result.error || 'Failed to apply names.';
                }
            } catch (e) {
                console.error('Error applying sheet contacts:', e);
                applySheetFeedback.style.color = 'red';
                applySheetFeedback.textContent = 'An unexpected error occurred.';
            }
        });
    }
});
