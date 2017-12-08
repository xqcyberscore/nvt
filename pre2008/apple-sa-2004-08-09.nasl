# OpenVAS Vulnerability Test
# $Id: apple-sa-2004-08-09.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Apple SA 2003-12-19
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

tag_summary = "The remote host is missing Security Update 2003-12-19.

Mac OS X contains a flaw that may allow a malicious user 
with physical access to gain root access. 

The issue is triggered when the Ctrl and c keys are pressed 
on the connected USB keyboard during boot and thus interrupting 
the system initialization. 

It is possible that the flaw may allow root access resulting 
in a loss of integrity.";

tag_solution = "http://docs.info.apple.com/article.html?artnum=61798";

if(description)
{
 script_id(14251);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8945);
 script_xref(name:"OSVDB", value:"7098");
 script_cve_id("CVE-2003-1011");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 
 name = "Apple SA 2003-12-19";
 
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Mac OS X Local Security Checks";
 script_family(family);
 
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/osx_pkgs", "ssh/login/uname");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

packages = get_kb_item("ssh/login/osx_pkgs");
if ( ! packages ) exit(0);

uname = get_kb_item("ssh/login/uname");
# MacOS X 10.2.8 and 10.3.2 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.2\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2003-12-19", string:packages) ) 
  {
	security_message(0);
  }
}
