# OpenVAS Vulnerability Test
# $Id: opera_large_javascript_array_vuln.nasl 3395 2016-05-27 12:54:51Z antu123 $
# Description: Opera web browser large javaScript array handling vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host is using Opera - an alternative web browser.
  This version is vulnerable to an issue when handling
  large JavaScript arrays.

  In particular, it is possible to crash the browser when performing
  various operations on Array objects with 99999999999999999999999
  or 0x23000000 elements.

  The crash is due to a segmentation fault and may be indicative
  of an exploitable memory corruption vulnerability,
  possibly resulting in arbitrary code execution.";

tag_solution = "Install Opera 7.50 or newer.";

# Ref: d3thStaR <d3thStaR@rootthief.com>

if(description)
{
  script_id(14248);
  script_version("$Revision: 3395 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-27 14:54:51 +0200 (Fri, 27 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1810");
  script_bugtraq_id(9869);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Opera web browser large javaScript array handling vulnerability");

  script_summary("Determines the version of Opera.exe");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"7.49")){
  security_message(0);
}

