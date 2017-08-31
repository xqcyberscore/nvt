# OpenVAS Vulnerability Test
# $Id: mozilla_default_perms.nasl 6467 2017-06-28 13:51:19Z cfischer $
# Description: Mozilla/Firefox default installation file permission flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com
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

tag_summary = "The remote host is using Mozilla and/or Firefox, an alternative web browser.
  The remote version of this software is prone to an improper file permission
  setting.

  This flaw only exists if the browser is installed by the Mozilla Foundation
  package management, thus this alert might be a false positive.

  A local attacker could overwrite arbitrary files or execute arbitrary code in
  the context of the user running the browser.";

tag_solution = "Update to the latest version of the software";

#  Ref: Max <spamhole@gmx.at>

if(description)
{
  script_id(15432);
  script_version("$Revision: 6467 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-28 15:51:19 +0200 (Wed, 28 Jun 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11166);
  script_cve_id("CVE-2004-0906");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mozilla/Firefox default installation file permission flaw");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

mozVer = get_kb_item("Firefox/Win/Ver");
if(mozVer)
{
  # check firefox version < 1.7.3
  if(version_is_less(version:mozVer ,test_version:"1.7.3"))
  {
    security_message(0);
    exit(0);
  }
}

tunBirdVer = get_kb_item("Thunderbird/Win/Ver");
if(!tunBirdVer){
  exit(0);
}

# check thunderbird version < 0.8
if(version_is_less(version:tunBirdVer,test_version:"0.8")){
  security_message(0);
}
