# Third-party notices

azure2csv is released under the MIT License (see `LICENSE`). It builds on the following public work.

## Azure Orphaned Resources (Dolev Shor)

The rules of the **Orphans** report (unattached disks, unused public IPs, orphaned NICs, unused NSGs and route
tables, empty App Service plans, idle load balancers, empty availability sets, unused NAT gateways, unlinked private
DNS zones, empty SQL elastic pools, empty resource groups) are adapted from the Azure Resource Graph queries of
<https://github.com/dolevshor/azure-orphan-resources>.

    MIT License - Copyright (c) Dolev Shor

## Microsoft Learn: "Azure resource types for move operations"

The **MoveSupport** report downloads and parses the public Microsoft Learn article
<https://learn.microsoft.com/azure/azure-resource-manager/management/move-support-resources>
(source: <https://github.com/MicrosoftDocs/azure-docs>) at run time. The article is licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0), (c) Microsoft Corporation. The data is not
redistributed with azure2csv; the report shows the source and the license.

## Microsoft documentation used for rules

The retirement rules, tenant-transfer checks, Azure Policy restriction checks (built-in policy definition IDs) and
finding recommendations are based on public Microsoft documentation (Azure Advisor service retirement guidance,
"Transfer an Azure subscription to a different Microsoft Entra directory", Azure Policy built-in definitions,
Microsoft Entra and Azure security best practices). Links are included in the report and in `findings.csv`.

## Optional components

- **ImportExcel** (Doug Finke, Apache 2.0) is used only when it is already installed, to create the Excel workbook.
  It is never downloaded or installed by azure2csv.
- **Az.Accounts** (Microsoft, MIT) is the only required module.
