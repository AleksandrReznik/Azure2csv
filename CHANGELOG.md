# Changelog

## 2.0.0 - 2026

A complete rewrite of the 2021 script. The promise of the original blog post ("I have more than 10 additional
reports but plan to publish them later") is kept: there are now 61 reports.

### New engine
- Data is collected with **Azure Resource Graph** and the Azure REST APIs. Large tenants take minutes instead of
  hours: v1 made at least two API calls per resource.
- **Only Az.Accounts is required.** The script calls the REST APIs itself, so changes in other Az modules can no
  longer break it (for example Az 16 removing `Actions` from role definitions).
- Runs on Windows PowerShell 5.1, PowerShell 7 and Azure Cloud Shell.
- Paging, retries with `Retry-After` for 429/5xx, and Resource Graph quota back-off are built in. Retries are shown
  on screen. When the saved sign-in has expired or needs MFA again, the script opens the Microsoft sign-in and
  continues. A non-interactive run stops instead and shows the `Connect-AzAccount` command to run.
- Each run writes `yyyyMMdd-HHmmss__general_log.txt` line by line, so the log is complete even when the window
  closes or the run stops. Started from Explorer ("Run with PowerShell"), the script waits for Enter before closing.
- Every collector reports its status in `coverage.csv` and the HTML report. One failing report never stops the run.
- Every run starts with a disclaimer (experimental, provided as is, findings are suggestions to verify manually). It
  is also at the top of `summary.html`, on the first sheet of the Excel workbook and in the run information file.

### Choosing reports
- `-Profile Quick | Standard | Full | Migration | Security | Governance` (default: Standard).
- `-Reports`, `-AddReports`, `-SkipReports` with 61 report names and 7 group names (tab completion).
- `-ListReports` shows the catalog, or the resolved selection, without contacting Azure.
- Lists (`-Reports RBAC, Policy`) also work when the script is started from cmd, a scheduler or with `pwsh -File`.
  A mistyped name or a stray word stops the run at once with one error line.
- v1 parameters (`-tenantID_Param`, `-subID_Param`, `-pathToSaveFiles`, `-createAllResourcesReport`,
  `-createRBACreports`, `-createPrivateDNSreport`) still work.
- New scope parameters: `-ExcludeSubscriptionId` and `-ManagementGroupId`.

### Configuration snapshot (opt-in, part of `-Profile Full`)
- **`Snapshot`:** `snapshot\` holds one JSON file per object in a path that mirrors its Azure ID: every resource with
  its properties uncut (a CSV cell is cut at 32,000 characters, the file is not), the rows of 14 more Resource
  Graph tables (DNS records, firewall policy rules, backup policies, App Service configuration...), and the role,
  policy, lock, diagnostic, child resource and Entra objects the other selected reports collected.
- **`ArmTemplates`:** Azure's own template export of every resource group as ARM JSON and Bicep
  (`-TemplateFormat Both | Json | Bicep`), written exactly as Azure returns it, with `templates\index.csv` and
  `templates\notExported.csv` (what Azure reported as missing). Resource groups with more than 200 resources are
  exported in parts.
- **`ChildResources`:** what Resource Graph does not list, read with list calls below about 40 resource types:
  storage containers, shares and lifecycle policies, SQL firewall rules and retention, Service Bus and Event Hubs
  entities, Cosmos DB databases and containers, Automation schedules and variables, DNS record sets, private endpoint
  DNS zone groups, Key Vault key and secret names (never values) and more. The API version of each list comes from the
  resource provider and is corrected from Azure's answer when needed; `childResourceTypes.csv` shows what was asked.
- The values of well-known secret properties that Azure returns to a reader (ExpressRoute authorization keys, shared
  keys, passwords) are replaced with `(not exported)` in every output.
- This is a configuration snapshot and a starting point for rebuilding. It is not a backup: it holds no data and no
  secrets, and exported templates usually need editing before they deploy.

### New reports
- **Network:** VNets, subnets, peerings, NSGs, NSG rules (one row per rule, risk flag), route tables, routes,
  public IPs, private endpoints, private DNS links (one row per link); network interfaces; load balancers with
  frontends, rules and probes; application gateways with listeners, rules and backends, WAF policies; Azure Firewalls
  and firewall policies with every rule, IP groups; VPN and ExpressRoute gateways, connections, circuits, Virtual WAN,
  NAT gateways, Bastion; every DNS record set of public and private zones.
- **Compute:** VM migration profile (size, vCPU/RAM, OS, image, disks with LUN and caching, power state, Hybrid
  Benefit, agents, backup, IPs, marketplace plan), disks, scale sets, AKS, App Service plans and apps (runtime stack,
  TLS, host names, access restrictions), container registries, Container Apps and their environments.
- **Data:** storage accounts, Azure SQL servers, databases, managed instances, SQL Server on VMs (support status),
  Key Vaults, Cosmos DB, PostgreSQL and MySQL flexible servers, Azure Cache for Redis, Service Bus, Event Hubs,
  Event Grid.
- **Monitoring:** Log Analytics workspaces, Application Insights, alert rules with their action groups, data
  collection rules, autoscale settings.
- **Operations:**
  - backup items of all workloads
  - Automation accounts and runbooks (retiring runtimes)
  - optional code export (`AzureCode`, `code\` folder with `index.csv`): runbooks, DSC configurations, Logic Apps,
    Data Factory, Stream Analytics, template specs, deployment scripts, workbooks, dashboards, log alert queries,
    Sentinel analytics rules, API Management policies and APIs, custom policies and roles; `AppCode` (only when named)
    downloads Function App and Web App files
  - Advisor
  - retirements (built-in rules plus Advisor, with dates)
  - orphaned resources
  - optional cost per resource
- **Governance:** management group hierarchy; Azure Policy assignments (including those inherited from management
  groups, and those at management groups without subscriptions), definitions, initiatives, exemptions and compliance;
  RBAC with resolved principal names, eligible and time-bound assignments (PIM for Azure resources) and deny
  assignments; Defender for Cloud plans; Azure Lighthouse delegations; registered resource providers; tenant-transfer
  impact.
- **Migration readiness:**
  - move support per resource type (Microsoft Learn data)
  - cross-resource-group / cross-subscription references
  - management locks
  - policies that restrict regions, resource types or VM sizes
- **Entra ID:**
  - tenant, domains and licenses
  - administrative units and directory settings (group creation, naming policy, guest access)
  - users (sign-in activity when permitted) and groups with their owners (members optional)
  - app registrations, enterprise apps and managed identities; who is assigned to each enterprise app (optional)
  - secret/certificate expiry
  - API permissions with risk flags, for every API an app registration names
  - directory roles and custom role definitions
  - Conditional Access policies, named locations and tenant-wide policies, when the sign-in has `Policy.Read.All`
    (a service principal; the sign-in of a user is told so in the coverage table)
- **Azure DevOps** (`ADO\` folder): organizations billed to the subscriptions, used by Managed DevOps Pools or agent
  VM extensions, or named with `-AdoOrganization`, read with the Az sign-in (no personal access token):
  - projects, Git repositories (size, last commit, branch policies), TFVC branches (size, last changeset, pipelines that
    map them), pipelines and classic release pipelines
  - service connections joined with their Entra identity, secret expiry and Azure roles
  - agent pools and agents, users and licenses, administrators
  - variable groups (names only), secure files, environments, deployment groups, extensions, service hooks
  - Azure Artifacts feeds (views, retention, upstream sources, feed permissions) and every package version (published
    or cached from upstream, publish date, download count and last download)
  - work item counts and processes
  - the other organizations connected to the tenant, listed only
  - `ADO\organizations.csv` plus one folder per organization; optional exports per project: pipelines
    (`AzureDevOpsPipelines`: YAML files, pipeline and release definitions) and the default branch of every repository
    and the latest version of every TFVC branch (`AzureDevOpsRepos`, only when named, up to `-AdoRepoMaxSizeMB`) and the
    packages published to the feeds
    (`AzureDevOpsPackages`, only when named: NuGet, npm, Maven, Python and Cargo, and Universal Packages through
    Microsoft's ArtifactTool; latest or all versions with `-AdoPackageVersions`, types with `-AdoPackageTypes`, versions
    up to `-AdoPackageMaxSizeMB` each and `-AdoPackagesMaxMB` in total)
- **findings.csv:** about 48 checks (Migration, Retirement, Security, Cost, Governance) with severity and
  recommendations.
- **summary.html:** a self-contained dashboard (no internet needed, light/dark theme, sortable tables).
- **Excel workbook:** built when the ImportExcel module is installed.
- **`-Mask`:** pseudonymizes names, IDs, UPNs, public IPs and tag values so results can be shared. The mapping file
  stays private, outside the run folder.

### Fixed v1 bugs
- `DiagnosticSettings` could show the previous resource's settings for resource types without diagnostic settings.
- Non-English characters became `?` in CSV files (Windows PowerShell 5.1 wrote ASCII). All files are now UTF-8
  with BOM.
- VMs whose network interface is in another resource group got empty IP/VNet/DNS columns.
- Public IPs were looked up by name only, so a same-named IP in another resource group could be reported.
- `Properties` was written as lossy `@{...}` text; it is now JSON.
- NIC NSG, subnet NSG and ASG values were calculated but never written. They are now columns (`NicNSG`,
  `SubnetNSG`, `ASG`, `RouteTable`).
- The reconnect code used an undefined variable. The tenant ID was effectively mandatory and an empty value
  crashed.
- Disabled subscriptions were not skipped; subscriptions from other tenants (Lighthouse) were mixed in.
- `CreatedTime`/`ChangedTime` were always empty; they are now read with `$expand=createdTime,changedTime`.
- The RBAC roles report repeated all built-in roles for every subscription. It is now deduplicated: custom roles
  plus the built-in roles that are actually used.
- Big tenants were slow because arrays were grown with `+=`.

### Changed output (for v1 users)
- Results go into a folder `azure2csv_<timestamp>_<tenant8>` (default: current directory) instead of the script
  folder.
- Multi-value cells use `; ` instead of line breaks, so no "AutoFit row height" is needed in Excel.
- Subscription and resource-group rows in `allResources.csv` contain real values instead of the `subscription`/`NA`
  placeholders. Filter them with the new `RowType` column.
- `RBAC_roles.csv` no longer has `SubscriptionID`/`SubscriptionName` columns, because it is deduplicated.
- The first 35 columns of `allResources.csv` and the first 11 columns of `RBAC_role_assignments.csv` keep the v1
  names and order; new columns are appended.

## 1.0 - 2021-10-15
- First public version: all resources, RBAC roles and assignments, private DNS zones and tags.
  <https://it4it.solutions/2021/10/15/inventory-all-azure-resources-to-csv-file/>
