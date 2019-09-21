use std::{ fs, io, env };
use std::error::Error;
use std::path::PathBuf;
use zip::ZipWriter;


const MAX_PATH: usize = 255;

macro_rules! try_or_skip {
    ( $e:expr, $path:expr ) => {
        if let Some(e) = $e {
            e
        } else {
            eprintln!("skip: {:?}", &$path);
            continue
        }
    }
}

fn truncation(mut name: String, max: usize) -> String {
    loop {
        if name.len() > max {
            name.pop();
        } else {
            return name;
        }
    }
}

fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let mut args = env::args().skip(1);
    let input = PathBuf::from(args.next().expect("input"));
    let output = PathBuf::from(args.next().expect("output"));

    for entry in input.read_dir()? {
        let entry = entry?;

        if entry.file_type()?.is_dir() {
            let path = entry.path();
            let dir_name = try_or_skip!(path.iter().last(), path);
            let dir_name = dir_name.to_string_lossy().into_owned();
            let dir_name = truncation(dir_name, MAX_PATH - ".cbz".len());

            let mut name = PathBuf::new();
            name.set_file_name(&dir_name);
            name.set_extension("cbz");

            println!("process: {:?}", path);

            let fd = fs::File::create(output.join(&name))?;
            let mut output = ZipWriter::new(fd);
            output.add_directory(dir_name, Default::default())?;

            for entry in path.read_dir()? {
                let path = entry?.path();

                if let Some(filename) = path.file_name() {
                    output.start_file(filename.to_string_lossy(), Default::default())?;
                    io::copy(&mut fs::File::open(path)?, &mut output)?;
                }
            }

            output.finish()?;
        }
    }

    Ok(())
}
