###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums_ok.nasl 4926 2017-01-03 08:49:00Z cfi $
#
# List File with no checksum violation or error
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103941");
  script_version("$Revision: 4926 $");
  script_name("File Checksums: Matches");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-03 09:49:00 +0100 (Tue, 03 Jan 2017) $");
  script_tag(name:"creation_date", value:"2013-08-21 16:07:49 +0200 (Wed, 21 Aug 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("policy_file_checksums.nasl");
  script_mandatory_keys("policy/checksum_ok");

  script_tag(name:"summary", value:"List files with no checksum violation or error");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit(0);
}

md5pass = get_kb_item("policy/md5cksum_ok");
sha1pass = get_kb_item("policy/sha1cksum_ok");

if (md5pass || sha1pass) {
  report = 'The following file checksums match:\n\n';
  report += 'Filename|Result|Errorcode;\n' + md5pass + sha1pass;
  log_message(data:report, port:0, proto:"ssh");
}

exit(0);
