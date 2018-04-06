###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_licensing_admin_console_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Citrix Licensing Administration Console Security Bypass And Denial Of Service Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to bypass
certain security restrictions and cause denial-of-service condition.

Impact Level: Application";

tag_affected = "Citrix Licensing Administration Console 11.6 and Prior.";

tag_insight = "The flaws are caused by errors in a third-party component that
is used by the administration console, which could allow an attacker to cause
a denial of service or gain unauthorized access to some license administration
functionality by tricking an administrator into visiting a malicious web site.";

tag_solution = "Upgrade to Citrix Licensing Administration Console 11.10 or later.
For updates refer to
http://www.citrix.com/downloads.html";

tag_summary = "This host is installed with Citrix Licensing Administration Console
and is prone to security bypass and denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801854");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1101");
  script_bugtraq_id(46529);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Citrix Licensing Administration Console Security Bypass And Denial Of Service Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43459");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1025123");
  script_xref(name : "URL" , value : "http://support.citrix.com/article/CTX128167");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0477");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_citrix_license_server_detect.nasl");
  script_require_keys("Citrix/License/Server/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get version from KB
ver = get_kb_item("Citrix/License/Server/Ver");
if(!ver){
  exit(0);
}

citrixVer = eregmatch(pattern:"([0-9.]+)", string:ver);
if(citrixVer[1])
{
  ## Check for Citrix License Server version 11.6 and prior.
  if(version_is_less_equal(version:citrixVer[1], test_version:"11.6.1")){
    security_message(0);
  }
}
