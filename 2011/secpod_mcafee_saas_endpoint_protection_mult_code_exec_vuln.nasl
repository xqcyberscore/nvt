###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcafee_saas_endpoint_protection_mult_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# McAfee SaaS Endpoint Protection ActiveX Controls Multiple Code Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application running the ActiveX control.
  Impact Level: System/Application";
tag_affected = "McAfee SaaS Endpoint Protection version 5.2.1 and prior.";
tag_insight = "- An error within the MyASUtil ActiveX control (MyAsUtil5.2.0.603.dll) when
    processing the 'CreateSecureObject()' method can be exploited to inject
    and execute arbitrary commands.
  - The insecure 'Start()' method within the MyCioScan ActiveX control
    (myCIOScn.dll) can be exploited to write to arbitrary files in the context
    of the currently logged-on user.";
tag_solution = "Upgrade to McAfee SaaS Endpoint Protection version 5.2.2 or later,
  For updates refer to http://www.mcafeeasap.com/";
tag_summary = "This host is installed with McAfee SaaS Endpoint Protection and is
  prone to multiple code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902562");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-3006", "CVE-2011-3007");
  script_bugtraq_id(49087);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("McAfee SaaS Endpoint Protection ActiveX Controls Multiple Code Execution Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45506");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025890");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10016");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_mcafee_saas_endpoint_protection_detect.nasl");
  script_require_keys("McAfee/SaaS/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("McAfee/SaaS/Win/Ver");
if(version)
{
  ## Check for McAfee SaaS Endpoint Protection versions prior to 5.2.2
  if(version_is_less(version:version, test_version:"5.2.2")) {
    security_message(0);
  }
}
