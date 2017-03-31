###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_int_sec_dos_aug_16.nasl 5534 2017-03-10 10:00:33Z teissa $
#
# Kaspersky Internet Security Multiple DOS Vulnerabilities (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "An attacker can exploit this vulnerability to cause a local denial of service attacks on any machine running Kaspersky Internet Security software.
  Impact Level: System/Application";
tag_affected = "Kaspersky Internet Security 16.0.0";
tag_insight = "This flaw occurs due to a specially crafted native API call which can cause an access violation in KLIF kernel driver.";
tag_solution = "Apply the patch from the advisory.";
tag_summary = "This host is running Kaspersky Internet Security 16.0.0 and is prone
  to multiple DOS vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107094");
  script_version("$Revision: 5534 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-10 11:00:33 +0100 (Fri, 10 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-11-22 13:17:56 +0100 (Tue, 22 Nov 2016)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2016-4304", "CVE-2016-4305", "CVE-2016-4307");
  script_name("Kaspersky Internet Security Multiple DOS Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://blog.talosintel.com/2016/08/vulnerability-spotlight-multiple-dos.html");

  script_tag(name:"qod", value:"30");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/IntNetSec/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");


kisVer = get_kb_item("Kaspersky/IntNetSec/Ver");
if(kisVer != NULL)
{
  if(version_is_equal(version:kisVer, test_version:"16.0.0"))
  {
    security_message(0);
    exit(0);
  }
}




