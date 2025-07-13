// Application Decommissioning System JavaScript

class DecommissionApp {
    constructor() {
        this.selectedComponents = new Set();
        this.dependencies = {
            adAccounts: [],
            dns: []
        };
        this.dependenciesLoaded = false;
        this.currentScreen = 'selection';
        
        this.initializeData();
        this.bindEvents();
        this.renderHierarchy();
    }

    initializeData() {
        this.hierarchyData = {
            "Full Application": {
                type: "root",
                icon: "fas fa-server",
                children: {
                    "TAS": {
                        type: "section",
                        icon: "fas fa-cube",
                        children: {
                            "Development": {
                                type: "org",
                                icon: "fas fa-code-branch",
                                children: {
                                    "dev-space-1": {
                                        type: "space",
                                        icon: "fas fa-layer-group",
                                        children: {
                                            "web-app-dev": { type: "component", icon: "fas fa-globe", status: "online" },
                                            "api-service-dev": { type: "component", icon: "fas fa-cogs", status: "online" },
                                            "database-dev": { type: "component", icon: "fas fa-database", status: "maintenance" }
                                        }
                                    },
                                    "dev-space-2": {
                                        type: "space",
                                        icon: "fas fa-layer-group",
                                        children: {
                                            "worker-service-dev": { type: "component", icon: "fas fa-tasks", status: "online" }
                                        }
                                    }
                                }
                            },
                            "Production": {
                                type: "org",
                                icon: "fas fa-code-branch",
                                children: {
                                    "prod-space-1": {
                                        type: "space",
                                        icon: "fas fa-layer-group",
                                        children: {
                                            "web-app-prod": { type: "component", icon: "fas fa-globe", status: "online" },
                                            "api-service-prod": { type: "component", icon: "fas fa-cogs", status: "online" },
                                            "database-prod": { type: "component", icon: "fas fa-database", status: "online" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "Utility": {
                        type: "section",
                        icon: "fas fa-tools",
                        children: {
                            "logging-service": { type: "component", icon: "fas fa-file-alt", status: "online" },
                            "monitoring-service": { type: "component", icon: "fas fa-chart-line", status: "online" },
                            "backup-service": { type: "component", icon: "fas fa-save", status: "maintenance" }
                        }
                    },
                    "WAP": {
                        type: "section",
                        icon: "fas fa-wifi",
                        children: {}
                    },
                    "SSRS": {
                        type: "section",
                        icon: "fas fa-chart-bar",
                        children: {}
                    },
                    "HCP": {
                        type: "section",
                        icon: "fas fa-cloud",
                        children: {
                            "hcp-storage": { type: "component", icon: "fas fa-hdd", status: "online" },
                            "hcp-gateway": { type: "component", icon: "fas fa-door-open", status: "online" }
                        }
                    }
                }
            }
        };

        this.mockDependencies = {
            adAccounts: [
                { id: "ad1", name: "SVC-WebApp-Dev", type: "Service Account", canUncheck: true },
                { id: "ad2", name: "SVC-API-Prod", type: "Service Account", canUncheck: true },
                { id: "ad3", name: "GRP-DevTeam", type: "Security Group", canUncheck: false },
                { id: "ad4", name: "SVC-Database", type: "Service Account", canUncheck: true },
                { id: "ad5", name: "GRP-AdminAccess", type: "Security Group", canUncheck: false }
            ],
            dns: [
                { id: "dns1", name: "dev-webapp.company.com", type: "CNAME", canUncheck: true },
                { id: "dns2", name: "api.company.com", type: "A Record", canUncheck: false },
                { id: "dns3", name: "db-cluster.internal.com", type: "CNAME", canUncheck: true },
                { id: "dns4", name: "monitoring.company.com", type: "A Record", canUncheck: true }
            ]
        };
    }

    bindEvents() {
        // See Dependencies button
        $('#seeDependenciesBtn').on('click', () => this.loadDependencies());
        
        // Submit for Review button
        $('#submitForReviewBtn').on('click', () => this.showReviewScreen());
        
        // Reset button
        $('#resetBtn').on('click', () => this.resetToSelection());
        
        // Confirmation text input
        $('#confirmationInput').on('input', () => this.validateConfirmation());
        
        // Confirm and Schedule button
        $('#confirmScheduleBtn').on('click', () => this.showChangeRequestModal());
        
        // Submit change request
        $('#submitChangeRequest').on('click', () => this.submitChangeRequest());
    }

    renderHierarchy() {
        const container = $('#hierarchyTree');
        container.empty();
        
        this.renderNode(this.hierarchyData, container, "");
    }

    renderNode(data, container, path) {
        Object.keys(data).forEach(key => {
            const node = data[key];
            const currentPath = path ? `${path}.${key}` : key;
            const hasChildren = node.children && Object.keys(node.children).length > 0;
            
            const nodeDiv = $(`
                <div class="tree-node ${this.getNodeClass(node.type)}" data-path="${currentPath}">
                    <div class="tree-item" data-type="${node.type}" data-path="${currentPath}">
                        ${hasChildren ? `<i class="fas fa-chevron-right expand-icon" data-path="${currentPath}"></i>` : '<span style="width: 16px; display: inline-block;"></span>'}
                        <input type="checkbox" class="tree-checkbox" data-path="${currentPath}">
                        <i class="${node.icon} tree-icon"></i>
                        <span class="tree-label">${key}</span>
                        ${node.status ? `<span class="badge status-badge status-${node.status}">${node.status}</span>` : ''}
                        ${node.type ? `<span class="badge badge-secondary tree-badge">${node.type}</span>` : ''}
                    </div>
                    <div class="tree-children" style="display: none;"></div>
                </div>
            `);
            
            container.append(nodeDiv);
            
            // Bind events for this node
            this.bindNodeEvents(nodeDiv, node, currentPath);
            
            // Render children if they exist
            if (hasChildren) {
                const childrenContainer = nodeDiv.find('.tree-children').first();
                this.renderNode(node.children, childrenContainer, currentPath);
            }
        });
    }

    bindNodeEvents(nodeDiv, node, path) {
        // Expand/collapse functionality
        nodeDiv.find('.expand-icon').on('click', (e) => {
            e.stopPropagation();
            this.toggleNode(nodeDiv);
        });
        
        // Checkbox selection with hierarchical behavior
        nodeDiv.find('.tree-checkbox').on('change', (e) => {
            e.stopPropagation();
            this.handleHierarchicalSelection(path, e.target.checked);
        });
        
        // Label click to toggle checkbox
        nodeDiv.find('.tree-label').on('click', (e) => {
            e.stopPropagation();
            const checkbox = nodeDiv.find('.tree-checkbox');
            if (checkbox.length) {
                checkbox.prop('checked', !checkbox.prop('checked')).trigger('change');
            }
        });
    }

    getNodeClass(type) {
        switch(type) {
            case 'org':
            case 'space':
                return 'child';
            case 'component':
                return 'grandchild';
            default:
                return '';
        }
    }

    toggleNode(nodeDiv) {
        const childrenDiv = nodeDiv.find('.tree-children').first();
        const expandIcon = nodeDiv.find('.expand-icon').first();
        
        if (childrenDiv.is(':visible')) {
            childrenDiv.slideUp(200);
            expandIcon.removeClass('expanded');
        } else {
            childrenDiv.slideDown(200);
            expandIcon.addClass('expanded');
        }
    }

    handleHierarchicalSelection(path, isSelected) {
        // Update current node
        this.updateNodeSelection(path, isSelected);
        
        // Update all children (recursive)
        this.updateChildrenSelection(path, isSelected);
        
        // Update all parents (recursive)
        this.updateParentSelection(path);
        
        // Update the selected components display
        this.updateSelectedComponentsFromTree();
        this.hideDependencies();
    }

    updateNodeSelection(path, isSelected) {
        const checkbox = $(`.tree-checkbox[data-path="${path}"]`);
        checkbox.prop('checked', isSelected);
        checkbox.prop('indeterminate', false);
        
        // Update visual state
        const treeItem = checkbox.closest('.tree-item');
        if (isSelected) {
            treeItem.addClass('selected');
        } else {
            treeItem.removeClass('selected');
        }
    }

    updateChildrenSelection(path, isSelected) {
        // Find all children of this path
        $(`.tree-checkbox[data-path^="${path}."]`).each((index, element) => {
            const childPath = $(element).data('path');
            // Only update direct and indirect children
            if (childPath.startsWith(path + '.')) {
                this.updateNodeSelection(childPath, isSelected);
            }
        });
    }

    updateParentSelection(path) {
        const pathParts = path.split('.');
        
        // Check each parent level
        for (let i = pathParts.length - 1; i > 0; i--) {
            const parentPath = pathParts.slice(0, i).join('.');
            this.updateParentCheckboxState(parentPath);
        }
    }

    updateParentCheckboxState(parentPath) {
        // Find all direct children of this parent
        const directChildren = $(`.tree-checkbox`).filter((index, element) => {
            const childPath = $(element).data('path');
            const childParts = childPath.split('.');
            const parentParts = parentPath.split('.');
            
            // Check if this is a direct child (one level deeper)
            return childParts.length === parentParts.length + 1 && 
                   childPath.startsWith(parentPath + '.');
        });

        if (directChildren.length === 0) return;

        let checkedCount = 0;
        let indeterminateCount = 0;

        directChildren.each((index, element) => {
            const $element = $(element);
            if ($element.prop('checked')) {
                checkedCount++;
            } else if ($element.prop('indeterminate')) {
                indeterminateCount++;
            }
        });

        const parentCheckbox = $(`.tree-checkbox[data-path="${parentPath}"]`);
        const parentTreeItem = parentCheckbox.closest('.tree-item');

        if (checkedCount === directChildren.length) {
            // All children are checked
            parentCheckbox.prop('checked', true);
            parentCheckbox.prop('indeterminate', false);
            parentTreeItem.addClass('selected');
        } else if (checkedCount > 0 || indeterminateCount > 0) {
            // Some children are checked or indeterminate
            parentCheckbox.prop('checked', false);
            parentCheckbox.prop('indeterminate', true);
            parentTreeItem.addClass('selected');
        } else {
            // No children are checked
            parentCheckbox.prop('checked', false);
            parentCheckbox.prop('indeterminate', false);
            parentTreeItem.removeClass('selected');
        }
    }

    updateSelectedComponentsFromTree() {
        this.selectedComponents.clear();
        
        // Get all checked checkboxes (not indeterminate)
        $('.tree-checkbox:checked').each((index, element) => {
            const $element = $(element);
            if (!$element.prop('indeterminate')) {
                const path = $element.data('path');
                const label = $element.closest('.tree-item').find('.tree-label').text();
                this.selectedComponents.add({ path, label });
            }
        });
        
        this.updateSelectedItemsDisplay();
    }

    updateSelectedItemsDisplay() {
        const container = $('#selectedItems');
        container.empty();
        
        if (this.selectedComponents.size === 0) {
            container.html('<p class="text-muted">No items selected</p>');
            return;
        }
        
        this.selectedComponents.forEach(item => {
            const itemDiv = $(`
                <div class="selected-item">
                    <span>${item.label}</span>
                    <i class="fas fa-times remove-item" data-path="${item.path}"></i>
                </div>
            `);
            
            itemDiv.find('.remove-item').on('click', () => {
                this.removeSelectedItem(item.path);
            });
            
            container.append(itemDiv);
        });
    }

    removeSelectedItem(path) {
        // Uncheck the corresponding checkbox and trigger hierarchical update
        const checkbox = $(`.tree-checkbox[data-path="${path}"]`);
        if (checkbox.length) {
            checkbox.prop('checked', false).trigger('change');
        }
    }

    hideDependencies() {
        this.dependenciesLoaded = false;
        $('#dependenciesSection').html(`
            <div class="text-center">
                <button id="seeDependenciesBtn" class="btn btn-outline-primary btn-lg">
                    <i class="fas fa-search mr-2"></i>
                    See Dependencies
                </button>
            </div>
        `);
        $('#seeDependenciesBtn').on('click', () => this.loadDependencies());
        $('#submitForReviewBtn').hide();
    }

    loadDependencies() {
        if (this.selectedComponents.size === 0) {
            alert('Please select at least one component before viewing dependencies.');
            return;
        }
        
        // Show loading state
        $('#seeDependenciesBtn').html('<i class="fas fa-spinner fa-spin mr-2"></i>Loading Dependencies...');
        $('#seeDependenciesBtn').prop('disabled', true);
        
        // Simulate API call
        setTimeout(() => {
            this.renderDependencies();
            this.dependenciesLoaded = true;
            $('#submitForReviewBtn').show();
        }, 1500);
    }

    renderDependencies() {
        const dependenciesHtml = `
            <div class="dependencies-content show">
                <div class="row">
                    <div class="col-md-6">
                        <div class="dependency-category">
                            <h6 class="font-weight-bold text-primary mb-3">
                                <i class="fas fa-users mr-2"></i>
                                AD Accounts/Groups
                            </h6>
                            <div id="adAccountsList">
                                ${this.renderDependencyList(this.mockDependencies.adAccounts)}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="dependency-category">
                            <h6 class="font-weight-bold text-primary mb-3">
                                <i class="fas fa-globe mr-2"></i>
                                DNS Entries
                            </h6>
                            <div id="dnsList">
                                ${this.renderDependencyList(this.mockDependencies.dns)}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        $('#dependenciesSection').html(dependenciesHtml);
    }

    renderDependencyList(dependencies) {
        return dependencies.map(dep => `
            <div class="dependency-item ${!dep.canUncheck ? 'disabled' : ''}">
                <input type="checkbox" ${!dep.canUncheck ? 'disabled' : ''} 
                       checked data-dep-id="${dep.id}" 
                       data-category="${dep.type || 'N/A'}">
                <div>
                    <div class="font-weight-medium">${dep.name}</div>
                    <small class="text-muted">${dep.type}</small>
                </div>
            </div>
        `).join('');
    }

    showReviewScreen() {
        if (!this.dependenciesLoaded || this.selectedComponents.size === 0) {
            alert('Please select components and load dependencies first.');
            return;
        }
        
        this.currentScreen = 'review';
        $('#selectionScreen').removeClass('active');
        $('#reviewScreen').addClass('active');
        
        this.renderReviewData();
    }

    renderReviewData() {
        // Generate and render consolidated review table
        this.renderConsolidatedReviewTable();
    }

    renderConsolidatedReviewTable() {
        // Generate stage dates
        const stage1Date = new Date();
        stage1Date.setDate(stage1Date.getDate() + 1);
        const stage2Date = new Date();
        stage2Date.setDate(stage2Date.getDate() + 2);

        const formatDate = (date) => {
            return date.toLocaleDateString('en-US', { 
                weekday: 'short', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        };

        // Get selected items
        const selectedComponents = Array.from(this.selectedComponents);
        const selectedAD = this.mockDependencies.adAccounts.filter(dep => 
            $('#dependenciesSection').find(`input[data-dep-id="${dep.id}"]:checked`).length > 0
        );
        const selectedDNS = this.mockDependencies.dns.filter(dep => 
            $('#dependenciesSection').find(`input[data-dep-id="${dep.id}"]:checked`).length > 0
        );

        // Generate status for items
        const generateItemStatus = (items, type, iconClass) => {
            return items.map(item => {
                const itemName = item.label || item.name;
                const stage1Status = Math.random() > 0.3 ? 'scheduled' : 'pending';
                const stage2Status = 'pending';
                
                return {
                    name: itemName,
                    type: type,
                    icon: iconClass,
                    stage1Status: stage1Status,
                    stage2Status: stage2Status,
                    subType: item.type || ''
                };
            });
        };

        const componentStatuses = generateItemStatus(selectedComponents, 'Application Components', 'fa-cube');
        const adStatuses = generateItemStatus(selectedAD, 'AD Accounts/Groups', 'fa-users');
        const dnsStatuses = generateItemStatus(selectedDNS, 'DNS Entries', 'fa-globe');

        // Create consolidated table
        const consolidatedTableHtml = `
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header bg-dark text-white">
                            <h6 class="mb-0">
                                <i class="fas fa-table mr-2"></i>
                                Consolidated Decommission Plan
                            </h6>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-hover mb-0 consolidated-table">
                                    <thead class="thead-light">
                                        <tr>
                                            <th class="border-right" style="width: 40%;">
                                                <i class="fas fa-list mr-2"></i>
                                                Components & Dependencies
                                            </th>
                                            <th class="text-center border-right" style="width: 30%;">
                                                <i class="fas fa-calendar mr-2"></i>
                                                Stage 1: Preparation<br>
                                                <small class="text-muted">${formatDate(stage1Date)}</small>
                                            </th>
                                            <th class="text-center" style="width: 30%;">
                                                <i class="fas fa-calendar-check mr-2"></i>
                                                Stage 2: Decommission<br>
                                                <small class="text-muted">${formatDate(stage2Date)}</small>
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${this.renderTableGroup('Application Components', componentStatuses)}
                                        ${this.renderTableGroup('AD Accounts/Groups', adStatuses)}
                                        ${this.renderTableGroup('DNS Entries', dnsStatuses)}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Insert the consolidated table after the timeline section
        $('.timeline').closest('.row').after(consolidatedTableHtml);
    }

    renderTableGroup(groupName, items) {
        if (items.length === 0) return '';
        
        const groupHeaderRow = `
            <tr class="table-group-header">
                <td colspan="3" class="bg-light font-weight-bold text-primary py-3">
                    <i class="fas ${items[0].icon} mr-2"></i>
                    ${groupName} (${items.length} items)
                </td>
            </tr>
        `;
        
        const itemRows = items.map(item => `
            <tr class="table-item-row">
                <td class="border-right">
                    <div class="d-flex align-items-center">
                        <i class="fas ${item.icon} text-muted mr-3"></i>
                        <div>
                            <div class="font-weight-medium">${item.name}</div>
                            ${item.subType ? `<small class="text-muted">${item.subType}</small>` : ''}
                        </div>
                    </div>
                </td>
                <td class="text-center border-right">
                    <span class="badge ${this.getStatusBadgeClass(item.stage1Status)} status-badge-lg">
                        <i class="fas ${this.getStatusIcon(item.stage1Status)} mr-1"></i>
                        ${this.getStatusText(item.stage1Status)}
                    </span>
                </td>
                <td class="text-center">
                    <span class="badge ${this.getStatusBadgeClass(item.stage2Status)} status-badge-lg">
                        <i class="fas ${this.getStatusIcon(item.stage2Status)} mr-1"></i>
                        ${this.getStatusText(item.stage2Status)}
                    </span>
                </td>
            </tr>
        `).join('');
        
        return groupHeaderRow + itemRows;
    }

    getStatusIcon(status) {
        switch(status) {
            case 'scheduled': return 'fa-clock';
            case 'in-progress': return 'fa-spinner fa-spin';
            case 'completed': return 'fa-check';
            case 'failed': return 'fa-times';
            case 'pending': return 'fa-pause';
            default: return 'fa-question';
        }
    }

    getItemIcon(type) {
        switch(type) {
            case 'component': return 'fa-cube';
            case 'ad-account': return 'fa-user';
            case 'dns-entry': return 'fa-globe';
            default: return 'fa-circle';
        }
    }

    getStatusBadgeClass(status) {
        switch(status) {
            case 'scheduled': return 'badge-warning';
            case 'in-progress': return 'badge-info';
            case 'completed': return 'badge-success';
            case 'failed': return 'badge-danger';
            case 'pending': return 'badge-secondary';
            default: return 'badge-light';
        }
    }

    getStatusText(status) {
        switch(status) {
            case 'scheduled': return 'Scheduled';
            case 'in-progress': return 'In Progress';
            case 'completed': return 'Completed';
            case 'failed': return 'Failed';
            case 'pending': return 'Pending';
            default: return 'Unknown';
        }
    }

    validateConfirmation() {
        const expectedText = 'CONFIRM DECOMMISSION APPLICATION COMPONENTS';
        const enteredText = $('#confirmationInput').val().trim();
        const isValid = enteredText === expectedText;
        
        $('#confirmScheduleBtn').prop('disabled', !isValid);
        
        if (isValid) {
            $('#confirmScheduleBtn').removeClass('btn-danger').addClass('btn-success');
        } else {
            $('#confirmScheduleBtn').removeClass('btn-success').addClass('btn-danger');
        }
    }

    resetToSelection() {
        this.currentScreen = 'selection';
        $('#reviewScreen').removeClass('active');
        $('#selectionScreen').addClass('active');
        $('#confirmationInput').val('');
        $('#confirmScheduleBtn').prop('disabled', true).removeClass('btn-success').addClass('btn-danger');
    }

    showChangeRequestModal() {
        $('#changeRequestModal').modal('show');
    }

    submitChangeRequest() {
        const changeRequestNumber = $('#changeRequestNumber').val().trim();
        const changeDescription = $('#changeDescription').val().trim();
        
        if (!changeRequestNumber) {
            alert('Please enter a change request number.');
            return;
        }
        
        // Simulate submission
        $('#submitChangeRequest').html('<i class="fas fa-spinner fa-spin mr-2"></i>Submitting...');
        $('#submitChangeRequest').prop('disabled', true);
        
        setTimeout(() => {
            $('#changeRequestModal').modal('hide');
            
            // Generate random request ID
            const requestId = 'DCM-' + new Date().getFullYear() + '-' + 
                             String(Math.floor(Math.random() * 100000)).padStart(5, '0');
            
            $('#requestId').text(requestId);
            $('#successModal').modal('show');
        }, 2000);
    }
}

// Initialize the application when DOM is ready
$(document).ready(() => {
    new DecommissionApp();
});