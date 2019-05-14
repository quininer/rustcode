extern crate zip;
extern crate humanesort;
extern crate encoding_rs as encoding;

use std::fs;
use std::env;
use std::io::{ self, Read, Write, Seek };
use humanesort::HumaneOrder;
use zip::read::{ ZipArchive, ZipFile };


struct SrcZip<R: Read + Seek> {
    pub zip: ZipArchive<R>
}

impl<R> SrcZip<R> where
    R: Read + Seek
{
    pub fn new(zip: ZipArchive<R>) -> Self {
        SrcZip { zip }
    }

    pub fn write_to(&mut self, output: &mut Write) -> io::Result<()> {
        let mut srcvec = Vec::new();

        for i in 0..self.zip.len() {
            let src = self.zip.by_index(i)
                .map_err(|err| io::Error::new(io::ErrorKind::NotFound, err))?;
            srcvec.push((i, src.name().to_string()));
        }

        srcvec.sort_unstable_by(|&(_, ref x), &(_, ref y)| HumaneOrder::humane_cmp(x, y));

        for (i, _) in srcvec {
            let src = self.zip.by_index(i)
                .map_err(|err| io::Error::new(io::ErrorKind::NotFound, err))?;

            Self::write_src_to(src, output)?;
        }

        Ok(())
    }

    fn write_src_to(mut input: ZipFile, output: &mut Write) -> io::Result<()> {
        enum State {
            Empty,
            Text,
            Command
        }

        let mut state = State::Empty;
        let mut buf = Vec::new();
        input.read_to_end(&mut buf)?;
        let (src, _, _) = encoding::GB18030.decode(&buf);

        for line in src.lines() {
            if line.trim().is_empty() {
                if let State::Text = state {
                    write!(output, "\n\n")?;
                }

                state = State::Empty;
                continue
            };

            if line.starts_with("#savetitle ") {
                write!(output, "{}\n\n\n", line.trim_left_matches("#savetitle").trim())?;
            } else if line.starts_with(";**") {
                write!(output, "{}\n\n", line.trim_left_matches(";**").trim())?;
            };

            if line.starts_with(';') || line.starts_with('#') {
                if let State::Text = state {
                    write!(output, "\n")?;
                }

                state = State::Command;
            } else {
                write!(output, "{}\n", line.trim_right().trim_right_matches(r"\n"))?;
                state = State::Text;
            }
        }

        Ok(())
    }
}


fn main() {
    let target = env::args().nth(1).unwrap();
    let output = env::args().nth(2).unwrap();

    let input = fs::File::open(&target).unwrap();
    let input = ZipArchive::new(input).unwrap();
    let mut output = fs::File::create(&output).unwrap();

    SrcZip::new(input)
        .write_to(&mut output).unwrap();
}
