import mongoose, { Schema, Document } from "mongoose";

export interface IBusinessUnit extends Document {
  name: string;
  label: string;
  createdAt?: Date;
  updatedAt?: Date;
}

const businessUnitSchema = new Schema<IBusinessUnit>(
  {
    name: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    label: {
      type: String,
      required: true,
      trim: true
    }
  },
  { timestamps: true }
);

export const BusinessUnit = mongoose.model<IBusinessUnit>("BusinessUnit", businessUnitSchema);
