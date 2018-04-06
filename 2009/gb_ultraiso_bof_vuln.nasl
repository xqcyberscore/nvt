###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultraiso_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# UltraISO Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause stack overflow or denial of service.

  Impact level: Application.";

tag_affected = "UltraISO version 9.3.3.2685 and prior.";
tag_insight = "This flaw is due to inadequate boundary check while processing 'CCD'
  or 'IMG' files.";
tag_solution = "Upgrade to UltraISO version 9.3.6.2750 or later
  updates refer, http://www.ezbsystems.com/ultraiso";
tag_summary = "This host is running UltraISO and is prone to Stack-Based Buffer
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800275");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1260");
  script_bugtraq_id(34363);
  script_name("UltraISO Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34581");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8343");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49672");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ultraiso_detect.nasl");
  script_require_keys("UltraISO/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("version_func.inc");

ultraVer = get_kb_item("UltraISO/Ver");
if(!ultraVer){
  exit(0);
}

# Grep for UltraISO maker version 9.3.3.2685 or prior.
if(version_is_less_equal(version:ultraVer, test_version:"9.3.3.2685")){
  security_message(0);
}
