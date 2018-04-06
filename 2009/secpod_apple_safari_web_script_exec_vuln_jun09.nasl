###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_web_script_exec_vuln_jun09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple Safari Web Script Execution Vulnerabilities - June09
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary web script
  in an https site's context and spoof an arbitrary https site by letting a
  browser obtain a valid certificate.
  Impact Level: Application";
tag_affected = "Safari version prior to 3.2.2 on Windows.";
tag_insight = "- Error in processes a '3xx' HTTP CONNECT response before a successful SSL
    handshake, which can be exploited by modifying the CONNECT response
    to specify a 302 redirect to an arbitrary https web site.
  - Error exists while the HTTP Host header to determine the context of a
    document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
    which can be exploited by modifying this CONNECT response, aka an
    'SSL tampering' attack.
  - Error is caused when application does not require a cached certificate
    before displaying a lock icon for an https web site, while sending the
    browser a crafted '4xx' or '5xx' CONNECT response page for an https request
    sent through a proxy server.
  - Detects http content in https web pages only when the top-level frame uses
    https. This can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'";
tag_summary = "This host has Safari browser installed and is prone to Web Script
  Execution vulnerabilities.";

tag_solution = "Upgrade to Safari version 5.0 or later
For updates refer to http://www.apple.com/safari";

desc2 = "
  *****
  Note: Vulnerability is related to CVE-2009-2066 and CVE-2009-2072
  *****

  Vulnerability Insight:
  - Error is caused when application does not require a cached certificate
    before displaying a lock icon for an https web site, while sending the
    browser a crafted '4xx' or '5xx' CONNECT response page for an https request
    sent through a proxy server.
  - Detects http content in https web pages only when the top-level frame uses
    https. This can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'

  Affected Software/OS:
  Safari version 4.0 and prior on Windows.";

if(description)
{
  script_xref(name : "URL" , value : "http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name : "URL" , value : "http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  script_oid("1.3.6.1.4.1.25623.1.0.900369");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apple Safari Web Script Execution Vulnerabilities - June09");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

# Check for Safari version < 3.2.2 (3.525.28.1)
if(version_is_less(version:safariVer, test_version:"3.525.28.1")){
  security_message(0);
}
# Check for Safari version 3.2.2 (3.525.28.1) <= 4.0 (4.30.17.0)
else if(version_in_range(version:safariVer, test_version:"3.525.28.1",
                         test_version2:"4.30.17.0")){
  security_message(data:desc2);
}
