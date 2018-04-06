###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_clickjacking_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Internet Explorer Clickjacking Vulnerability
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code and can retrieve sensitive information from the affected application.
  Impact Level: System";
tag_affected = "Windows Internet Explorer version 7.x on Windows.";
tag_insight = "Attackers will trick users into visiting an arbitrary URL via an onclick
  action that moves a crafted element to the current mouse position.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/download-ie.aspx";
tag_summary = "This host has installed Internet Explorer and is prone to
  clickjacking vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800347");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0369");
  script_name("Microsoft Internet Explorer Clickjacking Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7912");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

if( ! version = get_kb_item( "MS/IE/Version" ) ) exit( 0 );

# Check for Internet Explorer version 7.x
if( version =~ "^7\..*" ) {
  security_message( port:0 );
  exit( 0 );
}

exit( 99 );