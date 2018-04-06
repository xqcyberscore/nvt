###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pgp_desktop_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# PGP Desktop Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary codes in
  the context of an application via crafted program to cause denial of service.";
tag_affected = "PGP Corporation, PGP Desktop version 9.9.0.397 or prior on Windows.";
tag_insight = "This flaw is due to an error in the PGPwded.sys device driver when handling
  certain METHOD_BUFFERED IOCTL request that overwrites portions of memory.";
tag_solution = "Upgrade to PGP Desktop version 9.10 or later.
  For updates refer to http://www.pgp.com/products/desktop/index.html";
tag_summary = "This host is running PGP Desktop and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800216");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-5731");
  script_bugtraq_id(32991);
  script_name("PGP Desktop Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33310");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7556");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop/Win/Ver");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}


include("version_func.inc");

ver = get_kb_item("PGPDesktop/Win/Ver");
if(!ver){
  exit(0);
}

# Grep for version 9.9.0.397 and prior
if(version_is_less_equal(version:ver, test_version:"9.9.0.397")){
  security_message(0);
}
