###############################################################################
# OpenVAS Vulnerability Test
# $Id: aix_maintenance_level.nasl 7146 2017-09-15 12:38:49Z cfischer $
#
# AIX maintenance level
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14611");
  script_version("$Revision: 7146 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-15 14:38:49 +0200 (Fri, 15 Sep 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("AIX maintenance level");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("AIX Local Security Checks");
  script_dependencies("gather-package-list.nasl"); # The needed Host/AIX/oslevel kb key is never set here
  script_mandatory_keys("Host/AIX/oslevel");

  tag_summary = "This plugin makes sure the remote AIX server is running
  the newest maintenance package.";

  tag_solution = "http://www-912.ibm.com/eserver/support/fixes/";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

#here the list of last maintenance level
level4330=11;
level5100=8;
level5200=6;
level5300=2;

buf=get_kb_item("Host/AIX/oslevel");
if (!buf) exit(0);

 v=split(buf, sep:"-",keep: 0);
 if (isnull(v)) exit(0);
 osversion=int(v[0]);
 level=int(chomp(v[1]));

if (osversion==4330 && level < level4330)
{
str="The remote host is missing an AIX maintenance packages.
Maintenance level "+level+" is installed, last is "+level4330+".

You should install this patch for your system to be up-to-date.

Solution: http://www-912.ibm.com/eserver/support/fixes/";
 security_message(port:0, data:str);
  exit(0);
}

if (osversion==5100 && level < level5100)
{
str="The remote host is missing an AIX maintenance packages.
Maintenance level "+level+" is installed, last is "+level5100+".

You should install this patch for your system to be up-to-date.

Solution: http://www-912.ibm.com/eserver/support/fixes/";
 security_message(port:0, data:str);
  exit(0);
}

if (osversion==5200 && level < level5200)
{
str="The remote host is missing an AIX maintenance packages.
Maintenance level "+level+" is installed, last is "+level5200+".

You should install this patch for your system to be up-to-date.

Solution: http://www-912.ibm.com/eserver/support/fixes/";
 security_message(port:0, data:str);
  exit(0);
}

if (osversion==5300 && level < level5300)
{
str="The remote host is missing an AIX maintenance packages.
Maintenance level "+level+" is installed, last is "+level5300+".

You should install this patch for your system to be up-to-date.

Solution: http://www-912.ibm.com/eserver/support/fixes/";
 security_message(port:0, data:str);
  exit(0);
}
