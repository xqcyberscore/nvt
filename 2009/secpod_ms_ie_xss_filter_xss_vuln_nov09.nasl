###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_xss_filter_xss_vuln_nov09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer 'XSS Filter' XSS Vulnerabilities - Nov09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to conduct cross-site
scripting attacks on the affected system.

Impact Level: System";

tag_affected = "Microsoft Internet Explorer version 8 on Windows.";

tag_insight = "The XSS Filter used in 'response-changing mechanism' to conduct
XSS attacks against web sites that have no inherent XSS vulnerabilities, related
to the details of output encoding.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Internet Explorer and is prone to
Cross-Site Scripting vulnerability.

This NVT has been replaced by NVT secpod_ms10-002.nasl
(OID:1.3.6.1.4.1.25623.1.0.901097).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900898");
  script_version("$Revision: 9350 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4074");
  script_bugtraq_id(37135);
  script_name("Microsoft Internet Explorer 'XSS Filter' XSS Vulnerabilities - Nov09");
  script_xref(name : "URL" , value : "http://www.owasp.org/images/5/50/OWASP-Italy_Day_IV_Maone.pdf");
  script_xref(name : "URL" , value : "http://www.theregister.co.uk/2009/11/20/internet_explorer_security_flaw/");
  script_xref(name : "URL" , value : "http://hackademix.net/2009/11/21/ies-xss-filter-creates-xss-vulnerabilities/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


exit(66); ## This NVT is deprecated as addressed in secpod_ms10-002.nasl

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for MS IE version 8
if(ieVer =~ "^8\..*"){
  security_message(0);
}
