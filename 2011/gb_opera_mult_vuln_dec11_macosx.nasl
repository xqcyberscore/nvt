###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_dec11_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Opera Multiple Vulnerabilities - December11 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Opera version before 11.60.";
tag_insight = "Multiple flaws are due to
  - Improper handling of the number of .(dot) characters that conventionally
    exist in domain names of different top-level domains.
  - Implementation errors in the 'JavaScript' engine, 'Web Workers' and 'in'
    operator.
  - An error when handling certificate revocation related to 'corner cases'.
  - An error in Dragonfly in opera.";
tag_solution = "Upgrade to the Opera version 11.60 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802362");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2011-4684",
                "CVE-2011-4685", "CVE-2011-4686", "CVE-2011-4687");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 15:35:28 +0530 (Fri, 09 Dec 2011)");
  script_name("Opera Multiple Vulnerabilities - December11 (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1003/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1005/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/mac/1160/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version < 11.60
if(version_is_less(version:operaVer, test_version:"11.60")){
  security_message(0);
}
