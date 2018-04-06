###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ezip_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# eZip Buffer Overflow Vulnerability.
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploit will allow the attacker to execute arbitrary code on
  the system to cause the application to crash.
  Impact Level: Application";
tag_affected = "eZip version 3.0 and prior on Windows.";
tag_insight = "A boundary check error while processing specially crafted .zip compressed
  files leads to a stack based buffer overflow.";
tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://www.edisys.com/";
tag_summary = "The host is installed with eZip Wizard and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900525");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-24 05:22:25 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1028");
  script_bugtraq_id(34044);
  script_name("eZip Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8180");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49148");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ezip_detect.nasl");
  script_require_keys("eZip/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ezipVer = get_kb_item("eZip/Version");
if(!ezipVer){
  exit(0);
}

if(version_is_less_equal(version:ezipVer, test_version:"3.0")){
  security_message(0);
}
