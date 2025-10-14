// VulnDork Pro - Optimized JavaScript Application

class VulnDorkApp {
    constructor() {
        this.dorks = [];
        this.loading = false;
        this.selectedIntentCategory = 'All';
        this.selectedVulnType = 'all';
        
        this.initializeElements();
        this.bindEvents();
        this.initializeApp();
    }

    initializeElements() {
        // Form elements
        this.domainForm = document.getElementById('domainForm');
        this.domainInput = document.getElementById('domain');
        this.subdomainsCheckbox = document.getElementById('subdomains');
        this.advancedModeCheckbox = document.getElementById('advancedMode');
        this.generateBtn = document.getElementById('generateBtn');
        this.btnText = this.generateBtn?.querySelector('.btn-text');
        this.btnLoading = this.generateBtn?.querySelector('.btn-loading');
        
        // Log missing elements for debugging
        if (!this.domainForm) console.warn('domainForm element not found');
        if (!this.domainInput) console.warn('domainInput element not found');
        if (!this.generateBtn) console.warn('generateBtn element not found');

        // Results elements
        this.resultsVulnDropdown = document.getElementById('resultsVulnDropdown');
        this.resultsVulnDropdownMenu = document.getElementById('resultsVulnDropdownMenu');
        this.resultsVulnDropdownText = this.resultsVulnDropdown?.querySelector('.dropdown-text');
        this.resultsDropdownSearchInput = document.getElementById('resultsDropdownSearch');
        this.resultsDropdownContent = document.getElementById('resultsDropdownContent');

        // Download elements
        this.downloadDropdown = document.getElementById('downloadDropdown');
        this.downloadDropdownMenu = document.getElementById('downloadDropdownMenu');
        this.downloadItems = this.downloadDropdownMenu?.querySelectorAll('.download-item');

        // Validation and results
        this.domainValidation = document.getElementById('domainValidation');
        this.resultsSection = document.getElementById('resultsSection');
        this.resultsTitle = document.getElementById('resultsTitle');
        this.resultsCount = document.getElementById('resultsCount');
        this.resultsGrid = document.getElementById('resultsGrid');
        this.intentFilter = document.getElementById('intentFilter');

    }

    initializeApp() {
        document.querySelector('.main')?.classList.add('fade-in');
        this.domainInput?.focus();
        this.validateForm();
        this.initializeDropdowns();
    }

    initializeDropdowns() {
        // Results dropdown
        if (this.resultsVulnDropdown && this.resultsVulnDropdownMenu && this.resultsDropdownSearchInput) {
            document.addEventListener('click', (e) => {
                if (!this.resultsVulnDropdown.contains(e.target) && !this.resultsVulnDropdownMenu.contains(e.target)) {
                    this.closeResultsDropdown();
                }
            });

            this.resultsDropdownSearchInput.addEventListener('input', (e) => {
                this.filterResultsDropdownItems(e.target.value);
            });
        }

        // Download dropdown
        if (this.downloadDropdown && this.downloadDropdownMenu && this.downloadItems) {
            document.addEventListener('click', (e) => {
                if (!this.downloadDropdown.contains(e.target) && !this.downloadDropdownMenu.contains(e.target)) {
                    this.closeDownloadDropdown();
                }
            });

            this.downloadItems.forEach(item => {
                item.addEventListener('click', () => {
                    const format = item.dataset.format;
                    this.exportDorks(format);
                    this.closeDownloadDropdown();
                });
            });
        }
    }

    bindEvents() {
        if (this.domainForm) {
            this.domainForm.addEventListener('submit', (e) => this.handleFormSubmit(e));
        }
        
        if (this.domainInput) {
            this.domainInput.addEventListener('input', () => this.validateForm());
        }
        
        if (this.resultsVulnDropdown) {
            this.resultsVulnDropdown.addEventListener('click', () => this.toggleResultsDropdown());
        }
        
        if (this.downloadDropdown) {
            this.downloadDropdown.addEventListener('click', () => this.toggleDownloadDropdown());
        }
        

        if (this.intentFilter) {
            this.intentFilter.addEventListener('change', (e) => this.filterByIntent(e.target.value));
        }
        
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));
    }

    toggleResultsDropdown() {
        if (!this.resultsVulnDropdownMenu || !this.resultsVulnDropdown || !this.resultsDropdownSearchInput) return;

        this.resultsVulnDropdownMenu.classList.toggle('show');
        this.resultsVulnDropdown.setAttribute('aria-expanded', this.resultsVulnDropdownMenu.classList.contains('show'));

        if (this.resultsVulnDropdownMenu.classList.contains('show')) {
            this.resultsDropdownSearchInput.focus();
        }
    }

    closeResultsDropdown() {
        if (this.resultsVulnDropdownMenu && this.resultsVulnDropdown) {
            this.resultsVulnDropdownMenu.classList.remove('show');
            this.resultsVulnDropdown.setAttribute('aria-expanded', 'false');
        }
    }

    toggleDownloadDropdown() {
        this.downloadDropdownMenu?.classList.toggle('show');
        this.downloadDropdown?.classList.toggle('active');
    }

    closeDownloadDropdown() {
        this.downloadDropdownMenu?.classList.remove('show');
        this.downloadDropdown?.classList.remove('active');
    }

    filterResultsDropdownItems(searchTerm) {
        if (!this.resultsVulnDropdownMenu) return;

        const items = this.resultsVulnDropdownMenu.querySelectorAll('.dropdown-item');
        const term = searchTerm.toLowerCase();

        items.forEach(item => {
            const textElement = item.querySelector('.item-text');
            if (textElement) {
                const text = textElement.textContent.toLowerCase();
                item.style.display = text.includes(term) ? 'flex' : 'none';
            }
        });
    }

    selectResultsDropdownItem(item) {
        const type = item.dataset.type;
        const textElement = item.querySelector('.item-text');
        if (!textElement || !this.resultsVulnDropdownText || !this.resultsVulnDropdownMenu) return;

        this.selectedVulnType = type;
        this.resultsVulnDropdownText.textContent = textElement.textContent;

        this.resultsVulnDropdownMenu.querySelectorAll('.dropdown-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');

        this.closeResultsDropdown();
        this.renderDorks();
    }

    handleKeyboardShortcuts(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (!this.loading && this.domainInput?.value.trim()) {
                this.handleFormSubmit(e);
            }
        }
        
        if (e.key === 'Escape') {
            this.clearForm();
        }
    }

    validateForm() {
        if (!this.domainInput || !this.generateBtn || !this.domainValidation) return;
        
        const domain = this.domainInput.value.trim();
        const isValid = domain.length > 0 && this.isValidDomain(domain);
        this.generateBtn.disabled = this.loading || !isValid;
        
        if (domain.length === 0) {
            this.domainValidation.classList.remove('show', 'error');
            this.domainInput.style.borderColor = 'var(--border-primary)';
        } else if (isValid) {
            this.domainValidation.classList.remove('error');
            this.domainValidation.classList.add('show');
            this.domainValidation.textContent = '✓';
            this.domainInput.style.borderColor = 'var(--accent-success)';
        } else {
            this.domainValidation.classList.remove('show');
            this.domainValidation.classList.add('error');
            this.domainValidation.textContent = '✗';
            this.domainInput.style.borderColor = 'var(--accent-error)';
        }
    }

    isValidDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return domainRegex.test(domain) && domain.length <= 253 && domain.includes('.');
    }

    clearForm() {
        if (this.domainInput) this.domainInput.value = '';
        if (this.subdomainsCheckbox) this.subdomainsCheckbox.checked = false;
        if (this.advancedModeCheckbox) this.advancedModeCheckbox.checked = false;
        this.selectedVulnType = 'all';
        if (this.resultsVulnDropdownText) {
            this.resultsVulnDropdownText.textContent = 'All Types';
        }
        this.validateForm();
        this.domainInput?.focus();
    }

    async handleFormSubmit(e) {
        e.preventDefault();
        
        if (!this.domainInput || !this.subdomainsCheckbox || !this.advancedModeCheckbox) return;
        
        const domain = this.domainInput.value.trim();
        const includeSubdomains = this.subdomainsCheckbox.checked;
        const advancedMode = this.advancedModeCheckbox.checked;
        
        if (!domain) return;
        
        await this.generateDorks(domain, includeSubdomains, advancedMode);
    }

    async generateDorks(domain, includeSubdomains, advancedMode) {
        this.setLoading(true);
        
        try {
            const response = await fetch('/generate-dorks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    domain,
                    include_subdomains: includeSubdomains,
                    advanced_mode: advancedMode,
                }),
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            this.dorks = data;
            this.renderDorks();
            this.buildResultsTypeDropdown();
            this.showResultsSection();
            
            this.showNotification(`Generated ${data.length} dorks successfully!`, 'success');
            
        } catch (error) {
            console.error('Error generating dorks:', error);
            this.showNotification('Failed to generate dorks. Please check your connection and try again.', 'error');
        } finally {
            this.setLoading(false);
        }
    }

    setLoading(loading) {
        this.loading = loading;
        if (this.generateBtn) {
            this.generateBtn.disabled = loading || !this.domainInput?.value.trim();
        }
        
        if (loading) {
            if (this.generateBtn) this.generateBtn.classList.add('loading');
            if (this.btnText) this.btnText.style.opacity = '0';
            if (this.btnLoading) this.btnLoading.style.display = 'block';
        } else {
            if (this.generateBtn) this.generateBtn.classList.remove('loading');
            if (this.btnText) this.btnText.style.opacity = '1';
            if (this.btnLoading) this.btnLoading.style.display = 'none';
        }
    }


    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '12px 20px',
            borderRadius: '8px',
            color: 'var(--text-primary)',
            fontSize: '14px',
            fontWeight: '500',
            zIndex: '1000',
            transform: 'translateX(100%)',
            transition: 'transform 0.3s ease',
            maxWidth: '300px',
            wordWrap: 'break-word'
        });
        
        const colors = {
            success: 'var(--accent-success)',
            error: 'var(--accent-error)',
            warning: 'var(--accent-warning)',
            info: 'var(--accent-primary)'
        };
        notification.style.background = colors[type] || colors.info;
        
        document.body.appendChild(notification);
        
        setTimeout(() => notification.style.transform = 'translateX(0)', 100);
        
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => document.body.removeChild(notification), 300);
        }, 3000);
    }

    showResultsSection() {
        if (this.resultsSection) {
            this.resultsSection.style.display = 'block';
            this.resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }


    filterByIntent(intentCategory) {
        this.selectedIntentCategory = intentCategory;
        this.renderDorks();
    }

    getFilteredDorks() {
        let list = this.dorks;

        if (this.selectedIntentCategory !== 'All') {
            list = list.filter(d => d.intent_category === this.selectedIntentCategory);
        }

        if (this.selectedVulnType && this.selectedVulnType !== 'all') {
            list = list.filter(d => Array.isArray(d.tags) && d.tags.map(t => String(t).toLowerCase()).includes(this.selectedVulnType));
        }

        return list;
    }

    renderDorks() {
        const filteredDorks = this.getFilteredDorks();
        
        if (this.resultsTitle) this.resultsTitle.textContent = 'Generated Dorks';
        if (this.resultsCount) this.resultsCount.textContent = `${filteredDorks.length} dork${filteredDorks.length !== 1 ? 's' : ''} found`;
        
        if (this.resultsGrid) {
            this.resultsGrid.innerHTML = '';
            
            if (filteredDorks.length === 0) {
                const emptyMessage = document.createElement('div');
                emptyMessage.className = 'text-center text-muted';
                emptyMessage.style.padding = '2rem';
                emptyMessage.textContent = 'No dorks found for the selected category.';
                this.resultsGrid.appendChild(emptyMessage);
                return;
            }
            
            filteredDorks.forEach((dork, index) => {
                setTimeout(() => {
                    const dorkElement = this.createDorkElement(dork, index);
                    this.resultsGrid.appendChild(dorkElement);
                }, index * 50);
            });
        }
    }

    createDorkElement(dork, index) {
        const dorkCard = document.createElement('div');
        dorkCard.className = 'dork-card fade-in';
        
        // Header
        const header = document.createElement('div');
        header.className = 'dork-header';
        
        const dorkInfo = document.createElement('div');
        dorkInfo.className = 'dork-info';
        
        const dorkName = document.createElement('h3');
        dorkName.className = 'dork-name';
        dorkName.textContent = dork.name;
        dorkInfo.appendChild(dorkName);
        
        const dorkMeta = document.createElement('div');
        dorkMeta.className = 'dork-meta';
        
        const intentBadge = document.createElement('span');
        intentBadge.className = 'intent-badge';
        intentBadge.textContent = dork.intent_category;
        intentBadge.style.cssText = 'font-size: 10px; padding: 2px 6px; border: 1px solid var(--border-secondary); border-radius: 10px; color: var(--text-tertiary); background: var(--bg-tertiary);';
        dorkMeta.appendChild(intentBadge);
        
        const owaspInfo = document.createElement('span');
        owaspInfo.className = 'owasp-info';
        owaspInfo.textContent = `OWASP: ${dork.owasp}`;
        owaspInfo.style.cssText = 'font-size: 0.75rem; color: var(--text-tertiary); background: var(--bg-secondary); padding: 2px 6px; border-radius: var(--radius-sm); margin-left: 6px;';
        dorkMeta.appendChild(owaspInfo);
        
        dorkInfo.appendChild(dorkMeta);

        // Tags
        if (Array.isArray(dork.tags) && dork.tags.length) {
            const tagWrap = document.createElement('div');
            tagWrap.style.cssText = 'display: flex; flex-wrap: wrap; gap: 6px;';
            dork.tags.forEach(tag => {
                const chip = document.createElement('span');
                chip.textContent = String(tag);
                chip.style.cssText = 'font-size: 11px; padding: 4px 8px; border: 1px solid var(--border-primary); border-radius: 12px; color: var(--text-secondary); background: var(--bg-secondary);';
                tagWrap.appendChild(chip);
            });
            dorkInfo.appendChild(tagWrap);
        }
        header.appendChild(dorkInfo);
        
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn btn-secondary btn-sm';
        copyBtn.innerHTML = '<span class="btn-icon">📋</span> Copy';
        copyBtn.addEventListener('click', () => this.copyToClipboard(dork.dork, copyBtn));
        header.appendChild(copyBtn);
        
        dorkCard.appendChild(header);
        
        // Notes and code
        const notes = document.createElement('p');
        notes.className = 'dork-notes';
        notes.textContent = dork.notes;
        dorkCard.appendChild(notes);
        
        const code = document.createElement('code');
        code.className = 'dork-code';
        code.textContent = dork.dork;
        dorkCard.appendChild(code);
        
        return dorkCard;
    }

    async copyToClipboard(text, button) {
        try {
            await navigator.clipboard.writeText(text);
            
            const originalText = button.innerHTML;
            button.innerHTML = '<span class="btn-icon">✓</span> Copied!';
            button.style.background = 'var(--accent-success)';
            
            setTimeout(() => {
                button.innerHTML = originalText;
                button.style.background = '';
            }, 2000);
            
        } catch (err) {
            console.error('Failed to copy: ', err);
            this.fallbackCopyToClipboard(text);
        }
    }

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.cssText = 'position: fixed; left: -999999px; top: -999999px;';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            this.showNotification('Copied to clipboard!', 'success');
        } catch (err) {
            console.error('Fallback copy failed: ', err);
            this.showNotification('Failed to copy to clipboard', 'error');
        }
        
        document.body.removeChild(textArea);
    }

    exportDorks(format) {
        const filteredDorks = this.getFilteredDorks();
        let content, filename;
        
        if (format === 'txt') {
            content = filteredDorks.map(d => d.dork).join('\n');
            filename = 'vulndork-dorks.txt';
        } else if (format === 'json') {
            content = JSON.stringify(filteredDorks, null, 2);
            filename = 'vulndork-dorks.json';
        } else if (format === 'csv') {
            const headers = ['Category', 'Name', 'Dork', 'OWASP', 'Notes', 'Tags'];
            const csvContent = [
                headers.join(','),
                ...filteredDorks.map(d => [
                    `"${d.category}"`,
                    `"${d.name}"`,
                    `"${d.dork}"`,
                    `"${d.owasp}"`,
                    `"${d.notes}"`,
                    `"${d.tags.join(';')}"`
                ].join(','))
            ].join('\n');
            content = csvContent;
            filename = 'vulndork-dorks.csv';
        }
        
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification(`${format.toUpperCase()} file downloaded!`, 'success');
    }

    buildResultsTypeDropdown() {
        if (!this.resultsDropdownContent || !this.resultsVulnDropdownText) return;

        const typeCounts = new Map();
        this.dorks.forEach(d => {
            (Array.isArray(d.tags) ? d.tags : []).forEach(tag => {
                const key = String(tag).toLowerCase();
                typeCounts.set(key, (typeCounts.get(key) || 0) + 1);
            });
        });

        this.resultsDropdownContent.innerHTML = '';
        const allItem = this.createTypeDropdownItem('all', 'All Types', this.dorks.length);
        this.resultsDropdownContent.appendChild(allItem);
        allItem.classList.add('selected');
        this.selectedVulnType = 'all';
        this.resultsVulnDropdownText.textContent = 'All Types';

        const sorted = Array.from(typeCounts.entries()).sort((a,b) => b[1]-a[1]);
        sorted.forEach(([type, count]) => {
            const label = type.charAt(0).toUpperCase() + type.slice(1);
            const item = this.createTypeDropdownItem(type, label, count);
            this.resultsDropdownContent.appendChild(item);
        });
    }

    createTypeDropdownItem(type, label, count) {
        const item = document.createElement('div');
        item.className = 'dropdown-item';
        item.dataset.type = type;

        const icon = document.createElement('span');
        icon.className = 'item-icon';
        icon.textContent = '🏷️';
        const text = document.createElement('span');
        text.className = 'item-text';
        text.textContent = label;
        const cnt = document.createElement('span');
        cnt.className = 'item-count';
        cnt.textContent = String(count);

        item.appendChild(icon);
        item.appendChild(text);
        item.appendChild(cnt);

        item.addEventListener('click', () => this.selectResultsDropdownItem(item));
        return item;
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VulnDorkApp();
});

// Error handling
window.addEventListener('error', (e) => {
    console.error('Global error:', e.error);
});

window.addEventListener('unhandledrejection', (e) => {
    console.error('Unhandled promise rejection:', e.reason);
});