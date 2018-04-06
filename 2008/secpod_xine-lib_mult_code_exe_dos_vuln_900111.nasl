##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xine-lib_mult_code_exe_dos_vuln_900111.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: xine-lib Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

tag_impact = "Remote exploitation could allow execution of arbitrary code to
        cause the server to crash or denying the access to legitimate users.
 Impact Level : Application";

tag_solution = "Upgrade to xine-lib version 1.1.15
 http://xinehq.de/index.php/releases";

tag_affected = "xine-lib versions prior to 1.1.15 on Linux (All).";

tag_insight = "The flaws are due to,
        - errors when processing malformed Ogg files in demux_ogg_send_chunk()
          and send_header() functions in src/demuxers/demux_ogg.c
        - error when processing malformed V4L video in open_video_capture_device()
          function in src/input/input_v4l.c file.
        - error when processing malformed ID3 data in id3v22_interp_frame(),
          id3v23_interp_frame(), and id3v24_interp_frame() functions in
          src/demuxers/id3.c file.
        - error when processing malformed Real file in demux_real_send_chunk()
          function in src/demuxers/demux_real.c file.";


tag_summary = "The host is installed with xine-lib, which prone to multiple
 vulnerabilities.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900111");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-5235");
 script_bugtraq_id(30698);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("General");
 script_name("xine-lib Multiple Vulnerabilities");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_exclude_keys("ssh/no_linux_shell");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2382");
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=619869&group_id=9655");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}

include("ssh_func.inc");
 
 foreach item (get_kb_list("ssh/login/rpms"))
 {
        if("xine" >< item)
        {
                if(egrep(pattern:"(libxine(1)?|xine-lib)~(0\..*|1\.(0\..*|" +
				 "1(\.0?[0-9]|\.1[0-4])?))[^.0-9]", string:item))
		{
                        security_message(0);
			exit(0);
		}
	}
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
 	exit(0);
 }

 xineVer = ssh_cmd(socket:sock, cmd:"xine-config --version");
 ssh_close_connection();

 if(!xineVer){
 	exit(0);
 }

 if(egrep(pattern:"^(0\..*|1\.(0\..*|1(\.0?[0-9]|\.1[0-4])?))([^.0-9]|$)",
	  string:xineVer)){
 	security_message(port:0);
 } 
