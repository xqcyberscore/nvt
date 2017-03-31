###############################################################################
# OpenVAS Vulnerability Test
# $Id: xml.inc 4487 2016-11-14 07:41:39Z cfi $
#
# XML generation functions
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
#
# $Revision: 4487 $
#
###############################################################################


function xml_open_tag(tag, attributes) {
    res = '';

    res += '<' + tag;
    
    if (!isnull(attributes)) {
        foreach attr (keys(attributes)) {
            res += ' ' + attr + '="' + xml_escape(attributes[attr]) + '"';
        }
    }
    res += '>';

    return res;
}

function xml_close_tag(tag) {
    return '</' + tag + '>';
}

function xml_tagline(tag, attributes, value) {
    return xml_open_tag(tag:tag, attributes:attributes) + xml_escape(value) + xml_close_tag(tag);
}

function xml_open_comment() {
    return '<!--';
}

function xml_close_comment() {
    return '-->';
}

function xml_newline() {
    return '\n';
}

function xml_escape() {
  local_var escape_table, str, str_escaped, i;

  escape_table = make_array(
                      "&", "&amp;",
                      "'", "&apos;",
                      '"', "&quot;",
                      "<", "&lt;",
                      ">", "&gt;");

  str_escaped = "";

  str = _FCT_ANON_ARGS[0];
  max_idx = strlen(str);

  for (i = 0; i < max_idx; i++) {
    if (!isnull(escape_table[str[i]]))
      str_escaped += escape_table[str[i]];
    else
      str_escaped += str[i];
  }
  return str_escaped;
}

