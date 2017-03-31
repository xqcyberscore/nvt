###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_int_sec_mem_disc_aug_16.nasl 5070 2017-01-24 10:05:10Z antu123 $
#
# Kaspersky Internet Security KLDISK Driver Multiple Kernel Memory Disclosure Vulnerabilities (Windows)
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

tag_impact = "An attacker can exploit this vulnerability to leak sensitive information such as privileged tokens or kernel memory addresses that may
 be useful in bypassing kernel mitigations. An unprivileged user can run a program from user mode to trigger this vulnerability..
  Impact Level: System/Application";
tag_affected = "Kaspersky Internet Security 16.0.0.614";
tag_insight = "This flaws occurs due to the specially crafted IOCTL requests that can cause the driver to return out of bounds kernel memory.";
tag_solution = "Apply the patch from the advisory.";
tag_summary = "This host is running Kaspersky Internet Security 16.0.0.614 and is prone
  to multiple kernel memory disclosure vulnerabilities .";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107095");
  script_version("$Revision: 5070 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 11:05:10 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-11-24 13:17:56 +0100 (Thu, 24 Nov 2016)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2016-4306");
  script_name("Kaspersky Internet Security KLDISK Driver Multiple Kernel Memory Disclosure Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://www.talosintelligence.com/reports/TALOS-2016-0168/");

  script_tag(name:"qod", value:"30");
  script_summary("Check for the version of Kaspersky Total Security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/TotNetSec/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");


kisVer = get_kb_item("Kaspersky/TotNetSec/Ver");

if(kisVer != NULL)
{
  if(version_is_equal(version:kisVer, test_version:"16.0.0.614"))
  {
    security_message(0);
    exit(0);
  }
}

