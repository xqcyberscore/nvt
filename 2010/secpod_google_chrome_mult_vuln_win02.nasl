###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_win02.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Google Chrome Multiple Vulnerabilities - (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker bypass restrictions, disclose
  sensitive information or compromise a vulnerable system.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 4.0.249.89";
tag_insight = "The multiple flaws are due to:
  - An unspecified 'DNS' and 'fall-back' behavior of proxies, which could disclose
    sensitive information.
  - An integer overflow errors in the 'v8 engine', which could be exploited to
    execute arbitrary code.
  - An error related to the processing of 'ruby' tags, which could be exploited
    to execute arbitrary code.
  - An error related to 'iframe' data, which could leak redirection targets.
  - An error when displaying HTTP authentication dialogs, which could allow
    phishing attacks.
  - An integer overflow when deserializing 'sandbox' messages, which could allow
    code execution.";
tag_solution = "Upgrade to version 4.0.249.89 or later.
  http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902120");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0643", "CVE-2010-0644", "CVE-2010-0645", "CVE-2010-0646",
                "CVE-2010-0647", "CVE-2010-0649", "CVE-2010-0556");
  script_bugtraq_id(38177);
  script_name("Google Chrome Multiple Vulnerabilities - (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38545");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56212");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0361");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Feb/1023583.html");
  script_xref(name : "URL" , value : "http://sites.google.com/a/chromium.org/dev/Home/chromium-security/chromium-security-bugs");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

# Get for Chrome Version
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

# Check for Google Chrome version < 4.0.249.89
if(version_is_less(version:chromeVer, test_version:"4.0.249.89")){
  security_message(0);
}
