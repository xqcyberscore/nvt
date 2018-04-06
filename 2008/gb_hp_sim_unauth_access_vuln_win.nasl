###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sim_unauth_access_vuln_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# HP Systems Insight Manager Unauthorized Access Vulnerability (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow remote attackers to gain unauthorized
  access to the data.
  Impact Level: Application";
tag_affected = "HP SIM prior to 5.2 with Update 2 (C.05.02.02.00) on Windows";
tag_insight = "The flaw is due to an error in the application which allows
  unauthorized access to certain data.";
tag_solution = "Update to HP SIM version 5.2 with Update 2 (C.05.02.02.00)
  http://h20392.www2.hp.com/portal/swdepot/index.do";
tag_summary = "This host is running HP Systems Insight Manager (SIM) and is prone
  to security bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800033");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-4412");
  script_bugtraq_id(31777);
  script_name("HP Systems Insight Manager Unauthorized Access Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32287/");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01571962");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("http_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

port = 50000;
if(!port){
  exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

simVer = registry_get_sz(item:"Version",
         key:"SOFTWARE\Hewlett-Packard\Systems Insight Manager\Settings");
if(!simVer){
  exit(0);
}

# Grep for versions prior to 5.2 with update 2 (C.05.02.02.00)
if(version_is_less(version:simVer, test_version:"C.05.02.02.00")){
  security_message(port);
}
