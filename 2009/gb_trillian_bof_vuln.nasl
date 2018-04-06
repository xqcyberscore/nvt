###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trillian_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Trillian Buffer Overflow Vulnerability
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary code or
  to cause denial of service.";
tag_affected = "Trillian IM Client version 3.1.9.0 and prior.";
tag_insight = "The application fails to perform adequate boundary checks on user supplied
  data resulting in a parsing error while processing malformed DTD files.";
tag_solution = "Upgrade to Trillian IM Client version 4.2 or later
  For further updates refer, http://blog.ceruleanstudios.com";
tag_summary = "This host is installed with Trillian and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800265");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6563");
  script_bugtraq_id(28747);
  script_name("Trillian Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/41782");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/490772/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_trillian_detect.nasl");
  script_require_keys("Trillian/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

version = get_kb_item("Trillian/Ver");
if(!version){
  exit(0);
}

# Grep for Trillian version 3.1.9.0 or prior
if(version_is_less(version:version, test_version:"3.1.9.0")){
  security_message(0);
}
