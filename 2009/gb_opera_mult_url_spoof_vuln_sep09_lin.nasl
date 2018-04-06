###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_url_spoof_vuln_sep09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Opera Multiple URL Spoofing Vulnerabilities - Sep09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to conduct URL spoofing, and
  can cause Security Bypass in the victim's system.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.00 on Linux.";
tag_insight = "- Opera fails to handle a '\0' character or invalid wildcard character in a
    domain name in the subject's Common Name (CN) field of an X.509 certificate.
  - The Trusts root X.509 certificates signed with the MD2 algorithm, which
    makes it easier for man-in-the-middle attackers to spoof arbitrary SSL
    servers via a crafted server certificate.
  - Opera fails to check all intermediate X.509 certificates for revocation.
  - When a collapsed address bar is used, Opera does not properly update the
    domain name from the previously visited site to the currently visited site.
  - Opera fails to display all characters in Internationalized Domain Names
    (IDN) in the address bar.";
tag_solution = "Upgrade to Opera version 10.00
  http://www.opera.com/browser/download/";
tag_summary = "This host is installed with Opera Web Browser and is prone to
  Multiple Spoof URL vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800888");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3044", "CVE-2009-3045", "CVE-2009-3046",
                "CVE-2009-3047", "CVE-2009-3048", "CVE-2009-3049");
  script_name("Opera Multiple URL Spoofing Vulnerabilities - Sep09 (Linux)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/934/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/933/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/929/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/930/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/932/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/linux/1000/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");

if(isnull(operaVer))
{
  exit(0);
}

# Check for Opera Version < 10.00
if(version_is_less(version:operaVer, test_version:"10.00")){
  security_message(0);
}
