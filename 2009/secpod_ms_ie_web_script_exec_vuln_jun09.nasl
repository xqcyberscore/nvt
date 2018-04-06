###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_web_script_exec_vuln_jun09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer Web Script Execution Vulnerabilities
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
web script and spoof an arbitrary https site by letting a browser obtain a
valid certificate.

Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version prior to 8.0 on Windows.";

tag_insight =
"- Error exists while the HTTP Host header to determine the context of a
   document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
   and these can be exploited by modifying the CONNECT response, aka an
   'SSL tampering' attack.
 - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
   returned by a proxy server, which can be exploited by sending the browser
   a crafted 502 response page upon a subsequent request.";

tag_solution = "Upgrade to latest version,
http://www.microsoft.com/windows/internet-explorer/download-ie.aspx";

tag_summary = "This host has Internet Explorer installed and is prone to Web
Script Execution vulnerabilities.";

desc1 = "
  *****
  Note: Vulnerability is related to CVE-2009-2057 and CVE-2009-2069
  *****

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;
desc2 = "
  *****
  Note: Vulnerability is related to CVE-2009-2064
  *****

  Overview: This host has Internet Explorer installed and is prone to Web Script
  Execution vulnerability.

  Vulnerability Insight:
  - Detects http content in https web pages only when the top-level frame uses
    https. These can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'

  Impact:
  Successful exploitation will allow attacker to execute arbitrary web script.

  Affected Software/OS:
  Microsoft Internet Explorer version 8.0 and later on Windows";

desc3 = "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name : "URL" , value : "http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  script_oid("1.3.6.1.4.1.25623.1.0.900366");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Internet Explorer Web Script Execution Vulnerabilities");
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
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less(version:ieVer, test_version:"8.0")){
  security_message(data:string(desc1, desc3));
}
else if(version_in_range(version:ieVer, test_version:"8.0",
                         test_version2:"8.0.6001.18782")){
  security_message(data:string(desc2, desc3));
}
