###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_sharepoint_info_disc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft SharePoint Team Services Information Disclosure Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Attackers can exploit this issue via specially-crafted HTTP requests
to obtain the source code of arbitrary ASP.NET files from the backend database.
Impact Level: Application";

tag_affected = "Microsoft Office SharePoint Server 2007 12.0.0.6219 and prior.";

tag_insight = "This flaw is due to insufficient validation of user supplied data
passed into 'SourceUrl' and 'Source' parameters in the download.aspx in SharePoint
Team Services.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Microsoft SharePoint Server and is
prone to Information Disclosure Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800968");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3830");
  script_bugtraq_id(36817);
  script_name("Microsoft SharePoint Team Services Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976829");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53955");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507419/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("remote-detect-WindowsSharepointServices.nasl");
  script_mandatory_keys("MicrosoftSharePointTeamServices/version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

stsVer = get_kb_item("MicrosoftSharePointTeamServices/version");
if(isnull(stsVer)){
  exit(0);
}

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6219")){
  security_message(0);
}
