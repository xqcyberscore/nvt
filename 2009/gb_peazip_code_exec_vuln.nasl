###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_peazip_code_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# PeaZIP Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to exectue arbitrary code on
  the affected system via files containing shell metacharacters and commands 
  contained in a ZIP archive.";
tag_affected = "PeaZIP version 2.6.1 and prior on Windows.";
tag_insight = "The flaw is due to insufficient sanitation of input data while
  processing the names of archived files.";
tag_solution = "Update to PeaZIP version 2.6.2
  http://sourceforge.net/projects/peazip/files/";
tag_summary = "This host is installed with PeaZIP and is prone to Remote
  Code Execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800593");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2261");
  script_name("PeaZIP Remote Code Execution Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.vulnaware.com/?p=16018");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35352/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_peazip_detect_win.nasl");
  script_require_keys("PeaZIP/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

version = get_kb_item("PeaZIP/Win/Ver");
if(!version){
  exit(0);
}

# Grep for PeaZIP version 2.6.1 and prior
if(version_is_less_equal(version:version, test_version:"2.6.1")){
  security_message(0);
}
