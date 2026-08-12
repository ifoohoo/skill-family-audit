// Verbatim projection of the Foundation date-time format implementation.
// Each format entry carries the shape Ajv standalone codegen consumes:
// a record whose validate member is the projected implementation.
const DATE_TIME_PATTERN =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])[Tt]([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)$/;

function isValidDateTime(value) {
  if (typeof value !== "string" || !DATE_TIME_PATTERN.test(value)) return false;
  const [datePart] = value.split(/[Tt]/, 1);
  const [year, month, day] = datePart.split("-").map(Number);
  const roundTrip = new Date(Date.UTC(year, month - 1, day));
  return (
    roundTrip.getUTCFullYear() === year &&
    roundTrip.getUTCMonth() === month - 1 &&
    roundTrip.getUTCDate() === day
  );
}

const FORMATS = Object.freeze({ "date-time": Object.freeze({ validate: isValidDateTime }) });

export default FORMATS;
